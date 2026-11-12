# Fuzz targets

This directory holds the `cargo-fuzz` targets of Tenko: one program per parser of untrusted
input (DNS messages, DHCPv4 and DHCPv6 packets and options, cluster and enrollment messages,
HTTP bodies, uploaded files, answers of remote systems) that feeds it inputs made by
**libFuzzer**, a coverage-guided fuzzing engine, and stops at the first panic, failed
assertion, hang or allocation above the limits. A target asserts more than "does not panic"
where the parser has a round trip or an invariant: what decodes encodes again to the same
value, a reply fits its buffer, a limit holds.

Project rule (API-15): every new parser of network or file input ships with a target here, or
a hook in an existing one, before it merges.

## Layout

- `fuzz_targets/<target>.rs`: the targets, each registered as a `[[bin]]` in `Cargo.toml`.
- `limits.txt`: the `-max_len` of every target, with the production bound it comes from.
- `seeds/<target>/`: small valid inputs, one directory per target (every target has one).
- `Cargo.lock`: committed, so the weekly smoke builds the same dependency versions as the last
  gate; refresh it with `cargo update` in `fuzz/` when a target needs a newer dependency.
- `artifacts/`, `corpus/` and `coverage/`: written by `cargo fuzz`, ignored by git.

The fuzz crate is its own workspace, excluded from the main one. Some targets reach private
code through a module `fuzzing` that the product crate exports for them (`#[doc(hidden)]`,
not part of the API, for example `tenko_vault::transfer::fuzzing`); such a module only makes
code reachable and never changes what the product does.

## Running a target

Fuzzing needs a nightly toolchain and `cargo-fuzz`, on Linux or macOS (libFuzzer's sanitizer
runtime; on Windows use WSL). From the root of the repository:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
target=dns_codec
max_len="$(awk -v t="$target" '$1 == t { print $2 }' fuzz/limits.txt)"
mkdir -p "fuzz/corpus/$target"
cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
  -max_total_time=60 -rss_limit_mb=2048 -malloc_limit_mb=1024 -max_len="$max_len"
```

The first corpus directory collects what the run finds; the seed directory is only read.
Targets that link `tenko-api` embed the web UI: set `TENKO_UI_STUB=1` unless `ui/dist/` is
built, also for `cargo check`. To compile every target without fuzzing: `cd fuzz && cargo
check --locked` (the gate runs it).

## The limits on every run

Every run of the weekly smoke and of the security round passes:

- `-rss_limit_mb=2048`: a run whose resident memory passes 2 GiB fails.
- `-malloc_limit_mb=1024`: a single allocation above 1 GiB fails, so an allocation sized by a
  length field of the input rather than by a limit of the parser is reported, not survived.
- `-max_len=<n>` from `limits.txt`: the largest input the parser can meet in production (a
  receive buffer, a frame, a constant of the parser, an upload limit), plus the control octets
  the target reads first. Where production accepts megabytes, the target gets 64 KiB plus its
  control octets, which reaches the parser's own limits, and the line says so; a target that
  needs more for a branch of its own gets it, with the reason on its line. Without a
  `-max_len`, libFuzzer stays at 4,096 octets.

A target without a line in `limits.txt` fails both jobs, so a new target cannot run without
its bound.

## Adding a target

1. Write `fuzz_targets/<target>.rs`: a module comment that names the parser, the layout of the
   input (control octets first) and what the target asserts beyond "does not panic".
2. Register it as a `[[bin]]` in `Cargo.toml` (`test = false`, `doc = false`, `bench = false`).
   A new dependency edge of the fuzz crate changes `Cargo.lock`: run `cargo check` once
   without `--locked` and commit the lock file.
3. Add its line to `limits.txt`, sorted by name, with the production bound and where it comes
   from.
4. Add `seeds/<target>/` with a few small valid inputs made from the repository's own test
   vectors (fixtures, the bytes of a unit test), never a file from outside the repository.
5. Add its row to the table below.
6. Run it once for up to 60 seconds with one job (the command above) to see that it starts and
   reads its seeds, then `cd fuzz && cargo check --locked`.

The weekly smoke picks the target up from `cargo fuzz list`; no workflow changes.

## Minimizing

- A crash input: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
  writes the smallest input that still fails (`minimized-from-<hash>`).
- A corpus: `cargo +nightly fuzz cmin <target> fuzz/corpus/<target>` keeps the inputs that
  together reach the same coverage. A seed directory stays small by hand: a handful of inputs,
  each of a different shape.
- Reproduce one input: `cargo +nightly fuzz run <target> <file>` runs that input once.

## Where crashes go

- Locally: `fuzz/artifacts/<target>/` (`crash-`, `oom-`, `timeout-`, `slow-unit-` and the hash
  of the input).
- In the weekly smoke: the shard fails at its end and uploads `fuzz/artifacts/` as the workflow
  artifact `fuzz-artifacts-shard-<n>`, kept 14 days; the shard's job summary lists target,
  result, seconds and the number of crash files.
- In the security round: the row `fuzz.targets` fails and the inputs go into the round's
  evidence bundle.

A crash in a parser that a network peer reaches is a security issue: report it as
[`SECURITY.md`](../SECURITY.md) describes, not in a public issue, and keep the input out of
the repository until the fix is released. A crash input becomes a unit test of the parser
with the fix.

## Which job runs what

| Job | When | Targets | Budget |
|---|---|---|---|
| `Fuzz smoke` in `.github/workflows/ci.yml` | weekly (Sunday 03:17 UTC) and by hand (`workflow_dispatch`) | every target of `cargo fuzz list`, dealt round-robin over 6 parallel shards (target *i* of the sorted list to shard *i* mod 6) | 60 s per target after its build, one at a time per shard, within the job's 60 minutes |
| Row `fuzz.targets` of the security round (`deploy/security/fuzz.sh`, `.github/workflows/security-round.yml`) | every release, on the release commit | every target of `cargo fuzz list` | 120 s per target (`FUZZ_RELEASE_SECS`), four at a time |
| Row `fuzz.dns_wire` of the security round (`deploy/security/dnswire.py`) | every release | the running node: mutations of `seeds/dns_codec` over UDP and TCP | 10 minutes |

Both target jobs start from `seeds/<target>/` and carry the limits above. Keep a shard at about
11 targets: add a shard to the matrix and raise `FUZZ_SHARDS` in the job when the list passes
66 targets. A target that crashes does not stop the others of its shard or the other shards.
The weekly smoke is the regular pass on `main`; the release budget is the deeper pass on the
exact commit being shipped.

## Seeds

Each target's seeds are a few valid inputs of the shapes it reads, made from the repository's
own test vectors: the recorded messages under `crates/*/tests/fixtures/`, the byte strings of
unit tests, and the documented fixtures of the connectors converted to the shape the target
reads (a poll's snapshot, server WebSocket frames, answers split by `0xff`). Where a target
starts with control octets, its seeds carry them.

## Targets and the entry points they reach

The table grows as targets land.

| Target | Entry points it reaches |
|---|---|
| `scan_dns_message` | DNS messages of the probe: mDNS, LLMNR and reverse DNS answers (`tenko_scan::dns`) |
| `scan_snmp_message` | SNMPv3 messages and scoped PDUs (`tenko_scan::snmp::message`) |
| `scan_neighbor_tables` | The neighbor tables the probe reads: `/proc/net/arp`, `ip neigh` and `Get-NetNeighbor` CSV (`tenko_scan::methods::neighbors`) |
| `scan_lldp_cdp` | The passive neighbor frame parsers: LLDP (IEEE 802.1AB) and CDP version 2 TLVs, through the Ethernet/SNAP framing (`tenko_scan::frame::{lldp, cdp, ethernet}`) |
| `scan_arp` | The active-scan frame parsers: Ethernet, ARP (RFC 826), and the IPv4 and TCP parsers the SYN scan and the fingerprint read (`tenko_scan::frame::{ethernet, arp, ipv4, tcp}`) |
| `scan_dhcp_snoop` | The DHCP-snoop field parser (RFC 2131), through the Ethernet/IPv4/UDP framing; replaced by `tenko-dhcp`'s codec once it merges (`tenko_scan::frame::{dhcp, ethernet, ipv4}`) |
| `scan_ra` | The Router Advertisement parser of the DHCPv6 check (RFC 4861 section 4.2): the ICMPv6 message, its options (prefix information, MTU, source link-layer address, RDNSS) and the Router Solicitation builder (`tenko_scan::ra`) |
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
| `api_proxy_protocol` | The PROXY protocol reader of the API and UI listener, version 1 and version 2 with its TLVs, over a connection whose reads split the header anywhere: a header that parses is self-delimiting and within its version's limit, and the reader decides as the parser does on the whole input and hands on exactly the octets after the header (`tenko_api::server::proxy_protocol::{detect, parse, read_header}`) |
| `api_request_headers` | What the API reads from a request before it authenticates anyone: the client address, scheme and host under the trusted proxy rules (`X-Forwarded-For`, `-Proto`, `-Host`, the PROXY header of a trusted peer), `Host` and the URI authority, the CSRF guard and its `Origin` normalization, the session cookie and `Authorization`, and `Idempotency-Key`; a host or origin that validates validates again to itself, an untrusted peer's forwarded headers are never read, a trusted peer's client address is reached from the right through trusted hops only, and an unsafe method passes the CSRF guard only for its own or an allowed origin (`tenko_api::fuzzing`) |
| `import_files` | The readers of uploaded import files, as `POST /imports` hands them the file parts: the first octet picks the file name, the rest is the file; CSV in its encodings and delimiters, xlsx through the zip central directory reader and `calamine`, xls and ods refused; whatever reads stays within the sheet, row, column, cell and text limits of a real installation. Run it with an allocation limit (`-rss_limit_mb=2048 -malloc_limit_mb=1024`) so that an allocation sized by the input rather than by the limits is reported (`tenko_ipam::import::read::read_file`) |
| `upgrade_manifest` | The release manifest of the update check: the parser and validator, the release lookups and the asset URLs resolved against the manifest's URL (`tenko_api::dto::release::ReleaseManifest::parse`) |
| `cluster_messages` | The requests of the cluster port beyond `raft_payloads` and `node_config_payloads`: `Hello` and the version negotiation, heartbeats, the CSR of a renewal, joins, ingest batches, command subscriptions, the small `Cluster`, `Config` and `Metrics` requests and the identity in a caller's certificate (`tenko_cluster::server::fuzz_request`) |
| `metrics_peer_tiers` | The tiers of the dashboard's history that a controller receives from another controller, in the answer to `Metrics.History` and the `closed` of `Metrics.Snapshot`: the CBOR and the check of figures, steps, ring sizes, starts and numbers before the combination reads them (`tenko_api::dto::events::ControllerTiers::decode`) |
| `cluster_token` | The enrollment token a node presents to a controller, from the enrollment request and from the command line: `tnk2.<id>.<secret>.<fingerprint>` and `tnk1.<id>.<secret>` parsed from any text, the text of a parsed token read back to the same id, fingerprint and digest, the digest a controller looks the token up by, and the hexadecimal forms of a CA fingerprint and a digest read back from their rendering (`tenko_cluster::token::{EnrollmentToken, CaFingerprint, TokenDigest}`) |
| `webauthn_authdata` | WebAuthn authenticator data of registrations and assertions: the header, the attested credential with its COSE key and the extensions (`tenko_auth::webauthn::AuthenticatorData::parse`) |
| `webauthn_attestation` | The WebAuthn attestation object: its CBOR, the authenticator data and the `none` and `packed` statements with their certificate chains; the input starts with the 32-byte client data hash (`tenko_auth::webauthn::fuzzing::attestation_object`) |
| `auth_device_cookie` | The device cookie of a sign-in request, split into the marks of known devices: at most five, each of the shape of a 256-bit base64url secret, none twice, whatever the value (`tenko_auth::service::DeviceMarks::parse`) |
| `auth_sign_in_inputs` | What a sign-in reads from a client that is not signed in yet: the `clientDataJSON` of a passkey ceremony (type, challenge, origin, cross-origin fields), the credential id of an assertion, the ceremony id handed back, a TOTP code, a recovery code, the shape of a session cookie, and the base64url, base32 and hexadecimal decoders; client data passes only with the ceremony's type, the challenge, an allowed origin and no cross-origin claim, a TOTP code only for a step in the drift window after the last used one, a recovery code only for the code it normalizes to, and a decoder's output encodes and decodes to itself (`tenko_auth::webauthn::fuzzing::client_data`, `tenko_auth::webauthn::assertion_credential_id`, `tenko_auth::challenge::Ceremonies::take`, `tenko_auth::totp::verify`, `tenko_auth::recovery`, `tenko_auth::encoding`) |
| `webauthn_certificate` | The X.509 certificates of a `packed` attestation chain before any signature: the DER reader, then the refusal of unknown critical extensions and the key usage and path length of the issuers; the input is up to eight DER certificates in a row (`tenko_auth::webauthn::fuzzing::certificate_chain`) |
| `dns_codec` | DNS queries of the engine: the `domain` codec's parse of the header, question, OPT and TSIG, the answers built for them under the UDP and TCP limits, the FORMERR fallback, stored record data of every type and wire names (`tenko_dns::codec`, `tenko_dns::wire`, `tenko_core::dns::rdata`) |
| `dns_edns` | DNS queries through the whole query path of the engine: OPT and cookie parsing, BADVERS and the cookie modes, the authoritative resolver on a small zone, and the answer builder under random cookies, extended errors, forced truncation and required glue; the input starts with two control octets (`tenko_dns::respond`, `tenko_dns::cookie`, `tenko_dns::codec`) |
| `dns_tls_wire` | What DoT and DoH read before the query path: the PROXY protocol version 2 header and `X-Forwarded-For` of the reverse-proxy mode, the `dns` parameter of a DoH `GET` and its base64url, and the TTL walk of an answer behind `Cache-Control` (`tenko_dns::tls::proxy`, `tenko_dns::tls::doh`) |
| `dns_lists` | Block list text as a fetch or an upload hands it in: hosts files and domain lists with comments, IDN and the Adblock forms, their compiled version and its decoder, and the matcher of the query path (`tenko_dns::lists`) |
| `dns_tsig` | RFC 2136 UPDATE messages and the TSIG on them: the TSIG reader and verifier with BADKEY, BADSIG and BADTIME refusals, the UPDATE parser with its format rules (FORMERR, NOTZONE, NOTAUTH), the prerequisites against a few RRsets, the answer writer with an extended error, and the signed answer verified by the other side's MAC chain; the first octet is control: sign the body with the fuzz key, a time outside the fudge, a corrupted MAC, EDNS on the answer (`tenko_dns::tsig`, `tenko_dns::update::message`, `tenko_dns::update::prereq`) |
| `dhcp_v4` | DHCPv4 messages: the fixed header and the magic cookie, the walk over the option areas with option 52 overload and RFC 3396 concatenation, every typed option (client identifier and DUID, client FQDN, relay agent sub-options, PXE, vendor-identifying options), the domain search list and classless routes decoded and encoded again, and an OFFER built for every message that parses, which must read back (`tenko_dhcp::v4`) |
| `dhcp4_engine` | What the DHCPv4 server does with a datagram, on a configuration of three scopes (relayed, on the listener's link, not authoritative) with a reservation, a held lease and a trusted relay: up to four datagrams in turn, ten seconds apart, the commits applied between them, from the relay, the client, `0.0.0.0` or an untrusted sender, in either listener mode and every security profile; every reply fits the buffer, parses, is a BOOTREPLY with the request's `xid` and the message type the engine named, echoes option 82 as received, and offers or acknowledges only an address of a configured scope; the client's fingerprint and class facts, and the DDNS name of a committed lease, which is a host name under its zone (`tenko_dhcp::v4::engine::handle`, `tenko_dhcp::fingerprint`, `tenko_dhcp::class::facts`, `tenko_dhcp::ddns::names`) |
| `dhcp4_options` | The DHCPv4 option walk fed an options area behind a fixed header (the first octet puts the next 192 octets into `sname` and `file` for option 52): `option` and `option_data` checked against the instances the walk yields (one, a split, the RFC 3396 concatenation), and every typed parser on the joined value with its own invariants: address lists, client identifier and DUID, client FQDN, option 82 and option 43 sub-options, user class, architectures, network interface, machine identifier, vendor classes and vendor information, classless routes and the domain search list encoded again (`tenko_dhcp::v4`) |
| `dhcp4_relay_info` | Option 82 (RFC 3046) as a relay sends it, the first octet choosing the request around it (message type, `giaddr`, option 118, `ciaddr`): the sub-option parser walks every octet and its accessors return the first instance, the value reads back from the request also when split, scope selection follows link selection, option 118, `giaddr`, `ciaddr` and the listener in that order, and a reply carries the value back unchanged (`tenko_dhcp::v4::RelayAgentInfo`, `tenko_dhcp::v4::engine::select`) |
| `dhcp6_engine` | What the DHCPv6 server does with a message, on a configuration of three scopes (one per relay Interface-Id, one on the listener's link) with address and prefix delegation pools, reservations, a held lease and trusted relays: up to four messages in turn with the commits applied between them, from a trusted relay, a client on the link or an untrusted sender, in every security profile; every reply fits the buffer and parses, a relayed request gets one RELAY-REPL layer per relay with the Interface-Ids echoed, the innermost reply carries the transaction id, the server's and the client's DUIDs and a message type that answers the request's, and every address, prefix and committed binding lies in the scope's network or delegation pool (`tenko_dhcp::v6::engine::handle`) |
| `dhcp6_wire` | DHCPv6 messages (RFC 8415): the fixed header of a client, server or relay message, the option walk (every value inside the message, the octets walked adding up to the options area), every typed option (DUIDs, option request, client FQDN, link-layer address, user and vendor classes, address lists), the `IA_NA` and `IA_PD` options with their addresses, prefixes and status, the relay chain, the domain list encoded again to the octets it came from, the NTP server option, and a REPLY built for every message that parses with `IA_NA` options nested through `begin` and `end` (some limits too small, so that options are rewound), which must read back (`tenko_dhcp::v6`) |
| `dhcp6_relay` | A RELAY-FORW chain 0 to 7 deep built from the input (hop counts, link addresses some unspecified as RFC 6221 relays send them, Interface-Id and Client Link-Layer Address options before or after the Relay Message option) around a SOLICIT with the rest of the input as its options: `RelayChain::parse` finds the depth, the innermost link address, Interface-Id and link-layer address, and a RELAY-REPL chain built back from the parsed one has the same depth with the Interface-Ids echoed at the right layers (`tenko_dhcp::v6::RelayChain`) |
| `dns_referral` | An authority server's answer to the recursive resolver, against the bailiwick rules: the first octet picks the zone asked (the root, `test.`, `example.test.`), the rest is parsed and classified; a referral must go strictly below the zone with its glue within the zone (in-domain glue within the delegated zone), the records of an answer or a negative answer must be the zone's own, and what the engine stores is composed and must parse back unchanged (`tenko_dns::recurse::message::{parse, classify, compose}`) |
| `dns_cookie_client` | The client side of DNS cookies towards authority servers (RFC 7873 section 5.3): the cookie option, the full RCODE and the records of an answer, and a query built with cookies taken from the input, which must parse and return its own server cookie as an answer to itself, and be refused for another client cookie (`tenko_dns::recurse::net::{answer_cookie, full_rcode, build}`) |
| `dns_dnskey_ds` | DNSKEY and DS record data as the validator reads them: the first octet splits the input into the DNSKEY data and the DS data; the key parses or not, its tag is the RFC 4034 sum, a DS matches only when its tag, algorithm and a supported digest agree with the key, and an unsupported digest type never computes (`tenko_dns::validate::rrset::Key`, `tenko_dns::dnssec::crypto::{key_tag, ds_matches, ds_digest}`) |
| `dns_rrsig` | A DNS message whose RRsets are verified against the DNSKEY sets it holds, each signature's signer as the zone: the verification never spends more than the caps of the `KeyTrap` class allow per RRset and per query, a cap is reported as a cap, and a wildcard expansion names fewer labels than its owner (`tenko_dns::validate::rrset::verify`) |
| `dns_nsec3_proof` | The denial proofs: the first octet is the type asked, the rest a DNS message whose authority section holds NSEC or NSEC3 records of the question name's parent zone; the name error, NODATA, wildcard and delegation proofs run for the question name, the NSEC3 hashes of one step stay within the cap, and a cap is a cap fault rather than a proof (`tenko_dns::validate::{nsec, nsec3}`) |
| `dns_trust_anchor_xml` | The IANA trust anchor file (RFC 7958) as the shipped-anchors check and an operator's file read it: it parses with every key digest's DS record data carrying the fields read, or it is refused with a reason (`tenko_dns::anchors::xml::parse`) |
| `dns_trust_anchor_text` | The presentation form of a trust anchor key as `POST /dns/trust-anchors` and `tenko dns trust-anchor add` take it, DS record data or DNSKEY record data: it parses and writes back to a form that parses to the same data, or it is refused with a reason, also for text with characters of several octets (`tenko_dns::anchors::text::{parse_ds, parse_dnskey}`) |
| `krb_der` | Tenko's own DER codec of the Kerberos structures: the first octet chooses the structure (AP-REQ, AP-REP, ticket, `EncTicketPart`, authenticator, `EncAPRepPart`, AS and TGS requests and replies, `EncKDCRepPart`, `KRB-ERROR`, `KRB-PRIV` and its encrypted part, `PA-ETYPE-INFO2`, `METHOD-DATA`, `PA-ENC-TS-ENC`, `ChangePasswdData`, authorization data, the GSS-API `InitialContextToken`, `NegTokenInit` and `NegTokenResp`); a value that decodes encodes to octets that decode to the same value, and the GSS framing encodes back to its own octets (`tenko_krb::der`) |
| `krb_keytab` | The import parser of the MIT keytab format version 2: version 1 refused with its reason, holes skipped, the 32-bit key version, every count and length checked against the file; kept entries are AES with keys of the right length and every other entry is listed as refused (`tenko_krb::keytab`) |
| `krb_spnego` | The acceptor's negotiation (`tenko_krb::acceptor`): SPNEGO `negTokenInit` and `negTokenResp` legs (separated by `0xff 0xfe`) and raw Kerberos tokens, with the Samba lab key and the recorded time so that the recorded tokens reach the checks after the ciphers; NTLM, `NegoEx` and DCE style refused, `mechListMIC` both ways; a `Continue` answer is a `negTokenResp` and an established context has an AES acceptor subkey |
| `krb_ap_req` | The AP-REQ checks (`tenko_krb::acceptor`): an AP-REQ as it is, or one built from the plaintexts of a ticket and an authenticator encrypted under the lab keys, so that the `EncTicketPart` and authenticator decoders, the ticket flags and times, the GSS checksum, the PAC lookup and the AP-REP are fuzzed behind the ciphers |
| `krb_pac` | The PAC reader of [MS-PAC] (`tenko_krb::pac`): the buffers, the client information and the NDR of the logon information with its group, extra SID and resource group lists, read without the signature and verified with the lab key; each group appears once |
| `gss_mic` | RFC 4121 MIC tokens of GSS-TSIG (`tenko_krb::mic`): the first 28 octets are a token over the rest, verified in both directions under a fixed context key; a token signed over the rest verifies with its sequence number and is refused in the other direction and with a changed octet |
| `dns_tkey` | TKEY queries and GSS-TSIG on the update path (`tenko_dns::tkey`, `tenko_dns::tsig`): the TKEY parser with the record in the additional or the answer section, the handler of modes 3 and 5 over UDP and TCP (BADMODE, BADALG, BADNAME, the bounds of the context table, truncation for UDP), and GSS-TSIG verification of any message on a context negotiated beforehand from the recorded Samba exchange with the lab key, so that the context table, the deletion and the MIC check are reached; an answer is a response with the request's id |
| `store_snapshot` | The snapshot files of the store, as a node installs one a leader streams to it or reads its own back: the magic, the CBOR header, table and row records with their length limits, the end tag and the SHA-256, plain (format 1) or as a DEFLATE stream (format 2), under the bound of an install; the target can end the records itself with the right hash, so a file that checks out is reached too, and a format 1 file that is accepted ends with the SHA-256 of all before it (`tenko_store::raft::fuzzing`) |
