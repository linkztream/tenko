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
<!-- WP9.2 router advertisement parser (marked block). -->
| `scan_ra` | The Router Advertisement parser of the DHCPv6 check (RFC 4861 section 4.2): the ICMPv6 message, its options (prefix information, MTU, source link-layer address, RDNSS) and the Router Solicitation builder (`tenko_scan::ra`) |
<!-- End WP9.2 router advertisement parser. -->

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
| `dhcp6_wire` | WP9.1: DHCPv6 messages (RFC 8415): the fixed header of a client, server or relay message, the option walk (every value inside the message, the octets walked adding up to the options area), every typed option (DUIDs, option request, client FQDN, link-layer address, user and vendor classes, address lists), the `IA_NA` and `IA_PD` options with their addresses, prefixes and status, the relay chain, the domain list encoded again to the octets it came from, the NTP server option, and a REPLY built for every message that parses with `IA_NA` options nested through `begin` and `end` (some limits too small, so that options are rewound), which must read back (`tenko_dhcp::v6`) |
| `dhcp6_relay` | WP9.1: a RELAY-FORW chain 0 to 7 deep built from the input (hop counts, link addresses some unspecified as RFC 6221 relays send them, Interface-Id and Client Link-Layer Address options before or after the Relay Message option) around a SOLICIT with the rest of the input as its options: `RelayChain::parse` finds the depth, the innermost link address, Interface-Id and link-layer address, and a RELAY-REPL chain built back from the parsed one has the same depth with the Interface-Ids echoed at the right layers (`tenko_dhcp::v6::RelayChain`) |
<!-- WP10.1: the recursive resolver's targets (marked block). -->
| `dns_referral` | An authority server's answer to the recursive resolver, against the bailiwick rules: the first octet picks the zone asked (the root, `test.`, `example.test.`), the rest is parsed and classified; a referral must go strictly below the zone with its glue within the zone (in-domain glue within the delegated zone), the records of an answer or a negative answer must be the zone's own, and what the engine stores is composed and must parse back unchanged (`tenko_dns::recurse::message::{parse, classify, compose}`) |
| `dns_cookie_client` | The client side of DNS cookies towards authority servers (RFC 7873 section 5.3): the cookie option, the full RCODE and the records of an answer, and a query built with cookies taken from the input, which must parse and return its own server cookie as an answer to itself, and be refused for another client cookie (`tenko_dns::recurse::net::{answer_cookie, full_rcode, build}`) |
<!-- WP10.1: end. -->
<!-- WP10.2: the validator's targets (marked block). -->
| `dns_dnskey_ds` | DNSKEY and DS record data as the validator reads them: the first octet splits the input into the DNSKEY data and the DS data; the key parses or not, its tag is the RFC 4034 sum, a DS matches only when its tag, algorithm and a supported digest agree with the key, and an unsupported digest type never computes (`tenko_dns::validate::rrset::Key`, `tenko_dns::dnssec::crypto::{key_tag, ds_matches, ds_digest}`) |
| `dns_rrsig` | A DNS message whose RRsets are verified against the DNSKEY sets it holds, each signature's signer as the zone: the verification never spends more than the caps of the `KeyTrap` class allow per RRset and per query, a cap is reported as a cap, and a wildcard expansion names fewer labels than its owner (`tenko_dns::validate::rrset::verify`) |
| `dns_nsec3_proof` | The denial proofs: the first octet is the type asked, the rest a DNS message whose authority section holds NSEC or NSEC3 records of the question name's parent zone; the name error, NODATA, wildcard and delegation proofs run for the question name, the NSEC3 hashes of one step stay within the cap, and a cap is a cap fault rather than a proof (`tenko_dns::validate::{nsec, nsec3}`) |
| `dns_trust_anchor_xml` | The IANA trust anchor file (RFC 7958) as the shipped-anchors check and an operator's file read it: it parses with every key digest's DS record data carrying the fields read, or it is refused with a reason (`tenko_dns::anchors::xml::parse`) |
<!-- WP10.2: end. -->

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

## Weekly smoke

The `Fuzz smoke (Linux, weekly schedule)` job of `.github/workflows/ci.yml` (Sunday, or by hand with
`workflow_dispatch`) runs every target that `cargo fuzz list` prints for 60 seconds, with the
committed seed corpus when there is one. Since 41 targets in one job did not fit its 60 minutes
(each target is built first, then fuzzed), the job is a matrix of 4 shards: the sorted target list is
dealt out round-robin, target number *i* (counted from 0) to shard *i* mod 4, so the split is the same
on every run, every target runs exactly once, and a new target needs no edit of the workflow. A shard
holds 10 or 11 targets today; add a shard to the matrix and raise `FUZZ_SHARDS` in the job when the
list passes 44. A target that crashes does not stop the others of its shard or the other shards: the
shard fails at its end and uploads `fuzz/artifacts/` as `fuzz-artifacts-shard-<n>`. Each shard writes
a table to its job summary (target, result, seconds, number of crash files). To reproduce one target
run `cargo +nightly fuzz run <target>` as above; the workflow has no single-target input.
