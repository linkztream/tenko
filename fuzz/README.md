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
<!-- WP3.14 raw-socket frame parsers (marked block). -->
| `scan_lldp_cdp` | The passive neighbour frame parsers: LLDP (IEEE 802.1AB) and CDP version 2 TLVs, through the Ethernet/SNAP framing (`tenko_scan::frame::{lldp, cdp, ethernet}`) |
| `scan_arp` | The active-scan frame parsers: Ethernet, ARP (RFC 826), and the IPv4 and TCP parsers the SYN scan and the fingerprint read (`tenko_scan::frame::{ethernet, arp, ipv4, tcp}`) |
| `scan_dhcp_snoop` | The DHCP-snoop field parser (RFC 2131), through the Ethernet/IPv4/UDP framing; replaced by `tenko-dhcp`'s codec once it merges (`tenko_scan::frame::{dhcp, ethernet, ipv4}`) |
<!-- End WP3.14 raw-socket frame parsers. -->

| `connect_hass_ws_frame` | WebSocket frames and messages of the Home Assistant connector (`tenko_connect_hass::ws`) |
| `connect_hass_inventory` | Home Assistant registry and state answers mapped to hosts and vendor facts (`tenko_connect_hass::inventory`) |
| `connect_proxmox_inventory` | Proxmox VE API answers mapped to hosts (`tenko_connect_proxmox::inventory`) |
| `connect_unifi_answers` | UniFi controller answers mapped to devices, clients and ports (`tenko_connect_unifi`) |
| `kek_transfer` | The sealed key-encryption-key frames of a controller join (`tenko_vault::transfer`) |
| `raft_payloads` | The payloads between controllers: openraft messages, forwarded batches and receipts, store errors in status details, membership changes and the protocol messages that carry them (`tenko_cluster::wire`) |
| `xliff_pack` | Uploaded language packs: the XLIFF 2.0 reader, the validation against the key set, the ICU message checker, the language tags and the template round trip (`tenko_api::i18n`) |
| `node_config_payloads` | The node-sync payloads: configuration deltas and snapshots of `Config.Watch`, the frames of a watch stream joined and applied to a node configuration, command arguments, the `Config`, `Commands` and `Observations` messages, a probe's offer of its own configuration and a stored probe configuration row (`tenko_cluster::node_sync::payload`, `tenko_scan::control`) |
| `audit_export_jsonl` | The JSON lines of the audit export: records, checkpoints and test lines with the check of the canonical CBOR against the hash (`tenko_auth::audit_export::format::json`) |
| `audit_export_syslog` | The octet-counting decoder of the syslog sinks (RFC 6587) and the strict RFC 5424 parser (`tenko_auth::audit_export::format::syslog`) |
| `audit_export_cef` | The CEF parser and the render-parse round trip of attacker-chosen text in extension values (`tenko_auth::audit_export::format::cef`) |
| `backup_archive` | Backup files: the TKBK1 header and key slots, the chunk stream, the manifest and the key generation part (`tenko::backup::archive`) |
| `api_multipart` | The `multipart/form-data` body of `POST /imports`: the boundary of the content type and the file parts (`tenko_api::routes::import::{boundary_from_content_type, parse_multipart}`) |
| `upgrade_manifest` | The release manifest of the update check: the parser and validator, the release lookups and the asset URLs resolved against the manifest's URL (`tenko_api::dto::release::ReleaseManifest::parse`) |
| `cluster_messages` | The requests of the cluster port beyond `raft_payloads` and `node_config_payloads`: `Hello` and the version negotiation, heartbeats, the CSR of a renewal, joins, ingest batches, command subscriptions, the small `Cluster`, `Config` and `Metrics` requests and the identity in a caller's certificate (`tenko_cluster::server::fuzz_request`) |
| `webauthn_authdata` | WebAuthn authenticator data of registrations and assertions: the header, the attested credential with its COSE key and the extensions (`tenko_auth::webauthn::AuthenticatorData::parse`) |
| `webauthn_attestation` | The WebAuthn attestation object: its CBOR, the authenticator data and the `none` and `packed` statements with their certificate chains; the input starts with the 32-byte client data hash (`tenko_auth::webauthn::fuzzing::attestation_object`) |
| `dns_codec` | DNS queries of the engine: the `domain` codec's parse of the header, question, OPT and TSIG, the answers built for them under the UDP and TCP limits, the FORMERR fallback, stored record data of every type and wire names (`tenko_dns::codec`, `tenko_dns::wire`, `tenko_core::dns::rdata`) |
| `dns_edns` | DNS queries through the whole query path of the engine: OPT and cookie parsing, BADVERS and the cookie modes, the authoritative resolver on a small zone, and the answer builder under random cookies, extended errors, forced truncation and required glue; the input starts with two control octets (`tenko_dns::respond`, `tenko_dns::cookie`, `tenko_dns::codec`) |
| `dns_tls_wire` | What DoT and DoH read before the query path: the PROXY protocol version 2 header and `X-Forwarded-For` of the reverse-proxy mode, the `dns` parameter of a DoH `GET` and its base64url, and the TTL walk of an answer behind `Cache-Control` (`tenko_dns::tls::proxy`, `tenko_dns::tls::doh`) |
| `dns_lists` | Block list text as a fetch or an upload hands it in: hosts files and domain lists with comments, IDN and the Adblock forms, their compiled version and its decoder, and the matcher of the query path (`tenko_dns::lists`) |
| `dns_tsig` | RFC 2136 UPDATE messages and the TSIG on them: the TSIG reader and verifier with BADKEY, BADSIG and BADTIME refusals, the UPDATE parser with its format rules (FORMERR, NOTZONE, NOTAUTH), the prerequisites against a few RRsets, the answer writer with an extended error, and the signed answer verified by the other side's MAC chain; the first octet is control: sign the body with the fuzz key, a time outside the fudge, a corrupted MAC, EDNS on the answer (`tenko_dns::tsig`, `tenko_dns::update::message`, `tenko_dns::update::prereq`) |
| `dhcp_v4` | DHCPv4 messages: the fixed header and the magic cookie, the walk over the option areas with option 52 overload and RFC 3396 concatenation, every typed option (client identifier and DUID, client FQDN, relay agent sub-options, PXE, vendor-identifying options), the domain search list and classless routes decoded and encoded again, and an OFFER built for every message that parses, which must read back (`tenko_dhcp::v4`) |
| `dhcp4_options` | WP7.6: the DHCPv4 option walk fed an options area behind a fixed header (the first octet puts the next 192 octets into `sname` and `file` for option 52): `option` and `option_data` checked against the instances the walk yields (one, a split, the RFC 3396 concatenation), and every typed parser on the joined value with its own invariants: address lists, client identifier and DUID, client FQDN, option 82 and option 43 sub-options, user class, architectures, network interface, machine identifier, vendor classes and vendor information, classless routes and the domain search list encoded again (`tenko_dhcp::v4`) |
| `dhcp4_relay_info` | WP7.6: option 82 (RFC 3046) as a relay sends it, the first octet choosing the request around it (message type, `giaddr`, option 118, `ciaddr`): the sub-option parser walks every octet and its accessors return the first instance, the value reads back from the request also when split, scope selection follows link selection, option 118, `giaddr`, `ciaddr` and the listener in that order, and a reply carries the value back unchanged (`tenko_dhcp::v4::RelayAgentInfo`, `tenko_dhcp::v4::engine::select`) |

`fuzz/Cargo.lock` is committed, so the weekly smoke builds the same dependency versions as the last gate; refresh it with `cargo update` in `fuzz/` when a target needs a newer dependency.

## Running

Fuzzing requires a nightly toolchain and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run <target>
```

Targets that link `tenko-api` embed the web UI: set `TENKO_UI_STUB=1` unless `ui/dist/`
is built, also for `cargo check --bins`.

## Layout

- The fuzz crate is its own workspace and is excluded from the main workspace.
- `fuzz/artifacts/`, `fuzz/corpus/` and `fuzz/coverage/` are git-ignored.
- Small, meaningful seed corpora may be committed under `fuzz/seeds/<target>/`.
  Pass the directory as an extra corpus argument:
  `cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target>`.
