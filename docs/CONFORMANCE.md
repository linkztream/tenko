# Tenko DDI Conformance Matrix

DNS alone has roughly 300 RFCs, so Tenko DDI does not claim "all standards". Instead, this matrix publishes an explicit target phase for every specification Tenko implements, depends on, or deliberately skips (CON-08, API-17). Conformance tests per RFC are added as the engines land: Phase 2 for DNS, Phase 3 for DHCP.

Requirement IDs refer to [REQUIREMENTS.md](REQUIREMENTS.md). Phases are defined in [ROADMAP.md](ROADMAP.md).

## Status values

| Status | Meaning |
|---|---|
| Planned | Targeted in the listed phase, not yet implemented |
| Implemented | Implemented and covered by conformance tests |
| Partial | Implemented with documented gaps in Notes |
| Deliberately skipped | Will not be implemented; the reason is given in Notes |

Rules:

- A status changes in the same change that implements or tests the feature.
- "Implemented" requires a reference to the test.
- RFC titles are the official RFC titles, reproduced as published (including British spellings). Where an official title contains a spaced hyphen, a colon is shown instead.
- Target phase is the phase in which the specification is first delivered. Where a row splits by function, each part is listed with its phase. "n/a" is used only for deliberately skipped entries.

## RFC matrix

Area is one of DNS, DHCP or Other. Rows are sorted by RFC number.

| RFC | Title | Area | Target phase | Status | Requirements | Notes |
|---|---|---|---|---|---|---|
| 793 | Transmission Control Protocol | Other | 1 | Partial | SCAN-04 | The `tcp_syn` scan builds SYN and RST segments and reads SYN-ACK and RST flags, the window and the options; it is not a TCP stack. Superseded by RFC 9293. Tests in `crates/tenko-scan/src/frame/tcp.rs` |
| 826 | An Ethernet Address Resolution Protocol | Other | 1 | Implemented | SCAN-04 | The `arp_sweep` method builds ARP requests and reads replies over Ethernet/IPv4. Tests in `crates/tenko-scan/src/frame/arp.rs` |
| 1034 | Domain Names: Concepts and Facilities | DNS | 2 | Partial | DNS-01, DNS-03 | Section 5.3.3, the resolver's algorithm, is Implemented by the recursive resolver ([dns-resolver.md](dns-resolver.md) section 10): the closest zone cut known, referral following, CNAME restarts, name-server address lookups, a work budget per client query. Not done: QNAME minimisation (RFC 9156, WP10.3), so every server on the path is sent the full name. The other sections of the RFC are not recorded in this row yet. Tests in `crates/tenko-dns/src/recurse/tests.rs` (the table `CASES`, `every_case_of_e36_ends_within_the_budget_with_its_query_count`, `a_warm_cache_asks_only_the_zone_and_the_budget_bounds_the_rest`), `crates/tenko-dns/src/recurse/message/tests.rs`, and the lab round `recursion` (`deploy/compose/lab-dns/recursion.sh`) |
| 1035 | Domain Names: Implementation and Specification | DNS | 2 | Planned | DNS-01, MIG-15 | Zone file format also used for import and export |
| 1123 | Requirements for Internet Hosts: Application and Support | DNS | 2 | Planned | DNS-05 | |
| 1918 | Address Allocation for Private Internets | Other | 1 | Planned | IPAM-01 | Overlapping private space handled with tenants and VRFs |
| 1995 | Incremental Zone Transfer in DNS | DNS | 2 | Planned | DNS-09 | |
| 1996 | A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY) | DNS | 2 | Planned | DNS-09 | |
| 2131 | Dynamic Host Configuration Protocol | DHCP | 1 (snoop), 3 (server) | Partial | DHCP-01, SCAN-03 | Phase 1: the probe's `dhcp_snoop` method passively reads op, xid, chaddr, yiaddr and options 53, 12, 60, 61, 50 and 54 with a small local parser (`crates/tenko-scan/src/frame/dhcp.rs`), to be replaced by the codec below. Implemented: wire format (section 2 fixed header, section 3 magic cookie and message types, section 4.1 option areas, minimum size and reply limit, table 3 fields copied into a reply); the server and its state machine are Planned. Tests in `crates/tenko-dhcp/tests/` (`fixtures.rs`, `malformed.rs`, `alloc.rs`), fuzz target `dhcp_v4` |
| 2132 | DHCP Options and BOOTP Vendor Extensions | DHCP | 3 | Partial | DHCP-02, DHCP-15 | Includes option 6 (DNS servers) and option 42 (NTP). Implemented: wire format, typed reads and writes of options 1, 3, 6, 12, 15, 26, 28, 42, 43, 50 to 61, 66 and 67 (sections 3 to 9), every other option as raw octets; option 52 overload read and written. Option inheritance and custom definitions are Planned. Tests in `crates/tenko-dhcp/tests/` |
| 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | DNS | 2 | Planned | DNS-11, CONN-13 | |
| 2181 | Clarifications to the DNS Specification | DNS | 5 | Partial | DNS-03 | Data ranking (section 5.4) and the bailiwick rule of the recursive resolver; [dns-recursion-plan.md](plans/dns-recursion-plan.md) section 2.1. Implemented: within a message an authoritative answer section is used before authority data and glue, a non-authoritative answer is lame, records for names outside the zone that was asked are not used, and the addresses of a name server keep the origin that ranks highest (hints, sibling glue, in-domain glue, authoritative answer) so that a lower-ranked address never replaces an unexpired higher-ranked one (section 5.4.1). Not done: ranking of RRsets across messages, since the answer cache keeps whole answers and not RRsets. Tests in `crates/tenko-dns/src/recurse/message/tests.rs` (`an_answer_without_aa_is_lame`, the `a_referral_*` tests), `crates/tenko-dns/src/infra/tests.rs` (`cuts_names_and_servers_keep_the_contract`) and `crates/tenko-dns/src/recurse/tests.rs` (`the_ladder_and_the_bailiwick_leave_their_marks_in_the_caches`) |
| 2308 | Negative Caching of DNS Queries (DNS NCACHE) | DNS | 2 | Planned | DNS-02 | |
| 2317 | Classless IN-ADDR.ARPA delegation | DNS | 2 | Planned | DNS-22 | Automatic reverse zones from IPAM for shared /24s |
| 3004 | The User Class Option for DHCP | DHCP | 3 | Implemented | DHCP-03 | Option 77 read as sent and as its length-prefixed instances (section 2); a `user_class` match of a class holds for the whole value or one instance, so that the plain strings of Windows, ISC dhclient and iPXE match as well (WP8.4, `docs/dhcp.md` section 16.1). The server sends no user class. Tests in `crates/tenko-dhcp/src/class/tests.rs` and `tests/classes.rs` |
| 3011 | The IPv4 Subnet Selection Option for DHCP | DHCP | 3 | Planned | DHCP-04 | Option 118; scope selection before giaddr |
| 3046 | DHCP Relay Agent Information Option | DHCP | 3 | Partial | DHCP-04 | Option 82, circuit-id and remote-id. Implemented: wire format, the sub-options read in order and by code (1, 2, 5, 6, 11, 12) and the option echoed unchanged in a reply (section 2.2). Scope selection by sub-option is Planned. Tests in `crates/tenko-dhcp/tests/fixtures.rs` and `options.rs` |
| 3074 | DHC Load Balancing Algorithm | DHCP | 3 | Planned | DHCP-12 | Hash split between failover partners |
| 3203 | DHCP reconfigure extension | DHCP | n/a | Deliberately skipped | CON-10 | FORCERENEW is not supported by clients in practice; move jobs wait for observation instead |
| 3225 | Indicating Resolver Support of DNSSEC | DNS | 5 | Planned | DNS-13 | The DO bit set on every query to an authority; answered to clients since Phase 2 (ADR 0018 point 10) |
| 3396 | Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4) | DHCP | 3 | Implemented | DHCP-02 | Instances of one option joined in the order options field, file, sname (section 7); values above 255 octets written as consecutive instances, never into an earlier area. Tests in `crates/tenko-dhcp/tests/fixtures.rs` (the RFC 3397 split example) and `options.rs` |
| 3412 | Message Processing and Dispatching for the Simple Network Management Protocol (SNMP) | Other | 1 | Partial | SCAN-05 | SNMPv3 messages as a client: requests out, responses and reports in. No agent, no notification receiver. Tests in `crates/tenko-scan/src/snmp/` |
| 3414 | User-based Security Model (USM) for version 3 of the Simple Network Management Protocol (SNMPv3) | Other | 1 | Partial | SCAN-05 | Key localization, authentication, timeliness and engine discovery as a non-authoritative engine. SHA-1 (HMAC-SHA-1-96) is the only authentication protocol from this RFC; MD5 and DES are not supported. Tests in `crates/tenko-scan/src/snmp/`, including the key derivation of appendix A.3.2 |
| 3416 | Version 2 of the Protocol Operations for the Simple Network Management Protocol (SNMP) | Other | 1 | Partial | SCAN-05 | GetRequest and GetBulkRequest are sent; Response and Report are read. No SetRequest, no notifications. Tests in `crates/tenko-scan/src/snmp/` |
| 3442 | The Classless Static Route Option for Dynamic Host Configuration Protocol (DHCP) version 4 | DHCP | 3 | Planned | DHCP-02 | Option 121 in the option catalog |
| 3527 | Link Selection sub-option for the Relay Agent Information Option for DHCPv4 | DHCP | 3 | Planned | DHCP-04 | |
| 3597 | Handling of Unknown DNS Resource Record (RR) Types | DNS | 2 | Planned | DNS-01 | |
| 3645 | Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG) | DNS | 4 | Planned | DNS-28, CON-03 | AD secure dynamic updates via TKEY and Kerberos |
| 3646 | DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6) | DHCP | 3 | Planned | DHCP-09 | Options 23 and 24 |
| 3826 | The Advanced Encryption Standard (AES) Cipher Algorithm in the SNMP User-based Security Model | Other | 1 | Partial | SCAN-05 | AES-128 in CFB mode only; AES-192 and AES-256 are not supported. Tests in `crates/tenko-scan/src/snmp/` |
| 3942 | Reclassifying Dynamic Host Configuration Protocol version 4 (DHCPv4) Options | DHCP | 3 | Planned | DHCP-02 | Codes 224 to 254 are site-specific; custom definitions may use them |
| 4033 | DNS Security Introduction and Requirements | DNS | 2 (signing), 5 (validation) | Planned | DNS-12, DNS-13 | |
| 4034 | Resource Records for the DNS Security Extensions | DNS | 2 | Planned | DNS-12 | |
| 4035 | Protocol Modifications for the DNS Security Extensions | DNS | 2 (signing), 5 (validation) | Planned | DNS-12, DNS-13 | |
| 4361 | Node-specific Client Identifiers for Dynamic Host Configuration Protocol Version Four (DHCPv4) | DHCP | 3 | Planned | DHCP-01, DHCP-11 | Client identifiers of type 255 (IAID and DUID) accepted as client keys |
| 4388 | Dynamic Host Configuration Protocol (DHCP) Leasequery | DHCP | 5 | Planned | DHCP-04 | For relays that rebuild their state from the server; no Phase 3 requirement asks for it |
| 4509 | Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records | DNS | 5 | Planned | DNS-13 | DS digest type 2 in the chain walk; the signer publishes SHA-256 DS values since Phase 2 |
| 4578 | Dynamic Host Configuration Protocol (DHCP) Options for the Intel Preboot eXecution Environment (PXE) | DHCP | 3 | Implemented | DHCP-05 | Options 93 (client architecture), 94 (network interface) and 97 (machine identifier) read; 93 is a class match, so that the boot file per architecture is a policy; 97 is echoed in proxy DHCP replies; a PXE client with a boot file gets option 60 `PXEClient`, option 43 (discovery control 8 unless an option set holds 43), the `file` field and `siaddr`; proxy DHCP on port 4011 answers the boot server discovery without an address (WP8.4, `docs/dhcp.md` section 16). UEFI HTTP boot (`HTTPClient`) is answered with its URL and option 60. Tests in `crates/tenko-dhcp/tests/classes.rs`, E27's PXE rows in `deploy/compose/lab-dhcp` |
| 4701 | A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR) | DHCP | 3 | Planned | DHCP-13 | |
| 4702 | The Dynamic Host Configuration Protocol (DHCP) Client Fully Qualified Domain Name (FQDN) Option | DHCP | 3 | Partial | DHCP-13 | Option 81. Implemented: wire format, the flags S, O, E and N, both name encodings and partial names read; a server reply with RCODEs 255 in the encoding the flags give (sections 2 and 4). The DNS updates are Planned. Tests in `crates/tenko-dhcp/tests/` |
| 4703 | Resolution of Fully Qualified Domain Name (FQDN) Conflicts among Dynamic Host Configuration Protocol (DHCP) Clients | DHCP | 3 | Planned | DHCP-13 | Name protection |
| 4704 | The Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Client Fully Qualified Domain Name (FQDN) Option | DHCP | 3 | Planned | DHCP-13 | |
| 4795 | Link-local Multicast Name Resolution (LLMNR) | Other | 1 | Partial | SCAN-03 | Unicast reverse queries to known addresses, answers read from recorded responses in `crates/tenko-scan/tests/`. Tenko is not a responder and does not listen |
| 4861 | Neighbor Discovery for IP version 6 (IPv6) | Other | 1 (discovery), 3 (RA interplay) | Planned | SCAN-02, DHCP-10 | Passive ND discovery; M/O flag interplay with DHCPv6, which cannot set a default route |
| 5011 | Automated Updates of DNS Security (DNSSEC) Trust Anchors | DNS | 5 | Planned | DNS-13 | |
| 5071 | Dynamic Host Configuration Protocol Options Used by PXELINUX | DHCP | 3 | Implemented | DHCP-05 | Options 209 (configuration file), 210 (path prefix) and 211 (reboot time) in the catalog; a PXE client with a boot file gets them when they are set, asked for or not (PXELINUX does not always list them in option 55); 208 (the deprecated magic) needs a custom definition and goes out only when set (WP8.4). Tests in `crates/tenko-dhcp/tests/classes.rs` |
| 5107 | DHCP Server Identifier Override Suboption | DHCP | 3 | Planned | DHCP-04 | |
| 5155 | DNS Security (DNSSEC) Hashed Authenticated Denial of Existence | DNS | 2 | Planned | DNS-12 | NSEC3 |
| 5424 | The Syslog Protocol | Other | 1 | Planned | IAM-18 | Audit export |
| 5702 | Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC | DNS | 5 | Planned | DNS-13 | Validation of algorithms 8 and 10 (RFC 8624: MUST and MAY); Tenko never signs with RSA (ADR 0018) |
| 5908 | Network Time Protocol (NTP) Server Option for DHCPv6 | DHCP | 3 | Planned | DHCP-09, DHCP-15 | Option 56 |
| 6147 | DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers | DNS | 5 | Planned | DNS-03 | A later decision ([dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q14); the hook is named, nothing is built |
| 6238 | TOTP: Time-Based One-Time Password Algorithm | Other | 1 | Planned | IAM-06 | |
| 6303 | Locally Served DNS Zones | DNS | 5 | Implemented | DNS-03 | The reverse zones of the private, loopback, link-local and documentation ranges (34 zones, IPv4 and IPv6) are answered by the resolver unless a zone or a rule of the node covers them: the apex has the SOA of section 3 (the zone as the primary name server, `nobody.invalid.` as the mailbox) and an NS record, every name below it is NXDOMAIN with the SOA; `[dns.recursion] local_zones_except` lifts zones. Answered on the runtime, not on the worker, for now. Tests in `crates/tenko-dns/src/recurse/local.rs` (`local_zones_answer_and_exceptions_lift_them`) and `crates/tenko-dns/src/recurse/tests.rs` (`locally_served_names_never_reach_an_authority`), the lab row `rec.local` |
| 6605 | Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC | DNS | 5 | Planned | DNS-13 | Validation of algorithms 13 and 14; signing with 13 since Phase 2 (ADR 0018) |
| 6761 | Special-Use Domain Names | DNS | 5 | Partial | DNS-03 | `localhost`, `invalid`, `test`, `example` and the others of the registry never leave the resolver: a zone or rule of the node answers them, else the resolver answers NXDOMAIN with the zone's SOA; `[dns.recursion] local_zones_except` lifts a name (the lab lifts `test`). Not done: `example.com`, `example.net` and `example.org` of the registry are resolved as any name, and `localhost` is NXDOMAIN rather than the loopback addresses. Tests in `crates/tenko-dns/src/recurse/local.rs` and `crates/tenko-dns/src/recurse/tests.rs` (`locally_served_names_never_reach_an_authority`), the lab row `rec.local` |
| 6762 | Multicast DNS | Other | 1 | Partial | SCAN-02 | Queries from an ephemeral port (legacy unicast responses), unicast reverse queries to known addresses, and optional listening on a shared port 5353 during the run window. Tenko is not an mDNS responder. Answers read from recorded responses in `crates/tenko-scan/tests/` |
| 6763 | DNS-Based Service Discovery | Other | 1 | Partial | SCAN-02 | Browsing of service types, and reading of PTR, SRV and TXT records for TCP ports and OS hints. No service registration or announcing |
| 6840 | Clarifications and Implementation Notes for DNS Security (DNSSEC) | DNS | 5 | Planned | DNS-13 | The validator's rules for the DS chain, NSEC3 and the CD bit |
| 6842 | Client Identifier Option in DHCP Server Replies | DHCP | 3 | Planned | DHCP-01 | Option 61 echoed |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | DNS | 2 | Partial | DNS-06 | Default UDP buffer size 1232. The resolver's side towards authorities: every query carries an OPT record of version 0 with the payload size 1,232 (the one size; no step to 4,096 or 512) and the DO bit; a server that answers FORMERR or NOTIMP without an OPT record is asked once more without EDNS and remembered as taking none (section 6.2.2). Not done: EDNS version negotiation beyond version 0 (a BADVERS answer makes the server lame for the zone), and the EDNS options other than the cookie. Tests in `crates/tenko-dns/src/recurse/net/tests.rs` (`a_plain_exchange_answers_over_udp_with_edns_and_returns_the_server_cookie`, `formerr_without_opt_to_an_edns_query_is_asked_again_without_edns`, `a_second_formerr_is_not_retried_again`), `crates/tenko-dns/src/recurse/tests.rs` (the FORMERR case of `CASES`), the lab rows `rec.formerr` and `rec.formerr.marked` |
| 6939 | Client Link-Layer Address Option in DHCPv6 | DHCP | 3 | Planned | DHCP-11 | |
| 7344 | Automating DNSSEC Delegation Trust Maintenance | DNS | 2 | Planned | DNS-12 | CDS and CDNSKEY |
| 7646 | Definition and Use of DNSSEC Negative Trust Anchors | DNS | 5 | Planned | DNS-13 | Negative trust anchors with an expiry and an audit record |
| 7686 | The ".onion" Special-Use Domain Name | DNS | 5 | Implemented | DNS-03 | Answered NXDOMAIN by the resolver, never sent to an authority (`onion` is one of the zones of `crates/tenko-dns/src/recursion/mod.rs` `LOCAL_ZONES`). Tests in `crates/tenko-dns/src/recurse/local.rs` (`local_zones_answer_and_exceptions_lift_them`) and `crates/tenko-dns/src/recurse/tests.rs` (`locally_served_names_never_reach_an_authority`) |
| 7766 | DNS Transport over TCP: Implementation Requirements | DNS | 2 | Partial | DNS-05 | TCP is mandatory. The resolver's side towards authorities: a truncated UDP answer is asked again over TCP with the two-octet length prefix, and a server that truncates three answers in a row is asked over TCP from the start. Not done: each exchange opens a TCP connection and closes it, with no connection reuse, no pipelining and no idle-timeout handling towards authorities. Tests in `crates/tenko-dns/src/recurse/net/tests.rs` (`a_truncated_udp_answer_is_followed_over_tcp`, `a_query_that_asks_for_tcp_goes_straight_to_tcp`, `no_answer_over_tcp_is_a_timeout_within_the_deadline`), `crates/tenko-dns/src/infra/servers.rs` (`times_back_off_and_case_follow_the_pool`), `crates/tenko-dns/src/recurse/tests.rs` (the TC cases of `CASES`, `the_ladder_and_the_bailiwick_leave_their_marks_in_the_caches`), the lab rows `rec.tc` and `rec.big` |
| 7858 | Specification for DNS over Transport Layer Security (TLS) | DNS | 2 | Planned | DNS-14, DNS-15 | |
| 7860 | HMAC-SHA-2 Authentication Protocols in User-Based Security Model (USM) for SNMPv3 | Other | 1 | Partial | SCAN-05 | HMAC-SHA-224, -256, -384 and -512 with the digest lengths of the RFC. Keys and digests checked against independent values in `crates/tenko-scan/src/snmp/` |
| 7871 | Client Subnet in DNS Queries | DNS | 5 | Planned | DNS-03 | Scope to be decided; privacy implications (OPS-06); not used for view matching, which uses the query source |
| 7873 | Domain Name System (DNS) Cookies | DNS | 2 | Implemented | DNS-07 | The resolver's side towards authorities (the server side is the row for RFC 9018): every query carries a client cookie, the server cookie that comes back is kept per server in the infrastructure cache and sent from then on, an answer with another client cookie or a cookie to a query that sent none is not used (ignored over UDP, malformed over TCP), and BADCOOKIE is asked again once with the server cookie it carried (section 5.3). A server that returns no cookie costs nothing. Tests in `crates/tenko-dns/src/recurse/net/tests.rs` (`badcookie_is_asked_again_with_the_server_cookie_it_carried`, `badcookie_twice_is_an_error`, `an_answer_with_another_client_cookie_is_ignored_until_the_deadline`, `an_answer_with_another_client_cookie_over_tcp_is_malformed`, `an_answer_with_our_client_cookie_gives_the_server_cookie`), fuzz target `dns_cookie_client`; the cookies the engine hands out as a server are tested in `crates/tenko-dns/src/cookie.rs` |
| 7958 | DNSSEC Trust Anchor Publication for the Root Zone | DNS | 5 | Planned | DNS-13 | The root trust anchors shipped in the binary from the IANA XML, with their validity |
| 7969 | Customizing DHCP Configuration on the Basis of Network Topology | DHCP | 3 | Planned | DHCP-04 | Scope selection from relay information, link selection and the DHCPv6 link address |
| 8020 | NXDOMAIN: There Really Is Nothing Underneath | DNS | 5 | Planned | DNS-34 | Names below a cached NXDOMAIN are NXDOMAIN |
| 8078 | Managing DS Records from the Parent via CDS/CDNSKEY | DNS | 2 | Planned | DNS-12 | |
| 8080 | Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC | DNS | 5 | Planned | DNS-13 | Validation of algorithm 15; signing with 15 since Phase 2 (ADR 0018). Ed448 (16) is validated only if the crypto in use provides it |
| 8109 | Initializing a DNS Resolver with Priming Queries | DNS | 5 | Implemented | DNS-03 | Priming from the shipped hints (or the hints file of `[dns.recursion] hints`) at start, before the root NS set expires, after a change of the hints file and on request: `./NS` without RD, with EDNS and DO, tried at up to six root addresses; the answer replaces the hints as the root's servers; while it fails the hints stay in use and priming is tried again with a back-off from 1 second to 5 minutes, and the status shows `priming_failed`. The DNSSEC validation of the priming answer comes with WP10.2. Tests in `crates/tenko-dns/src/recurse/tests.rs` (`priming_from_a_hints_file_and_again_before_the_root_expires`, `priming_fails_with_unreachable_hints_and_names_the_problem`), `crates/tenko-dns/src/recurse/hints.rs` (`the_shipped_hints_name_thirteen_servers_with_both_families`, `a_lab_file_parses_and_bad_lines_are_refused`), the lab rows `rec.prime.file` and `rec.prime.again` |
| 8145 | Signaling Trust Anchor Knowledge in DNS Security Extensions (DNSSEC) | DNS | 5 | Planned | DNS-13 | A decision ([dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q10); off by default under Hardened if built |
| 8156 | DHCPv6 Failover Protocol | DHCP | 3 | Planned | DHCP-12 | |
| 8198 | Aggressive Use of DNSSEC-Validated Cache | DNS | 5 | Planned | DNS-34 | |
| 8375 | Special-Use Domain 'home.arpa.' | DNS | 5 | Implemented | DNS-03 | Never sent to an authority; answered from a zone of the node or NXDOMAIN with the zone's SOA (`home.arpa` is one of the zones of `crates/tenko-dns/src/recursion/mod.rs` `LOCAL_ZONES`). Tests in `crates/tenko-dns/src/recurse/local.rs` (`local_zones_answer_and_exceptions_lift_them`) and `crates/tenko-dns/src/recurse/tests.rs` (`locally_served_names_never_reach_an_authority`, which asks `host.home.arpa`) |
| 8415 | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) | DHCP | 3 | Planned | DHCP-09 | IA_NA, IA_PD, DUID, relay |
| 8482 | Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY | DNS | 2 | Planned | DNS-18 | |
| 8484 | DNS Queries over HTTPS (DoH) | DNS | 2 | Planned | DNS-14, DNS-15 | |
| 8509 | A Root Key Trust Anchor Sentinel for DNSSEC | DNS | 5 | Planned | DNS-13 | A decision ([dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q10) |
| 8624 | Algorithm Implementation Requirements and Usage Guidance for DNSSEC | DNS | 5 | Planned | DNS-13 | The validator supports every MUST and RECOMMENDED validation algorithm and digest; an unsupported algorithm makes a zone insecure, never bogus (RFC 4035 section 5.2) |
| 8767 | Serving Stale Data to Improve DNS Resiliency | DNS | 2 | Planned | DNS-23 | |
| 8806 | Running a Root Server Local to a Resolver | DNS | 5 | Planned | DNS-03 | An option, not the default ([dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q7) |
| 8906 | A Common Operational Problem in DNS Servers: Failure to Communicate | DNS | 5 | Implemented | DNS-03 | The fallback ladder towards authorities: no retry without EDNS on a timeout (DNS flag day 2019); a timeout is retried with EDNS, FORMERR or NOTIMP without an OPT record once without it, a truncated answer over TCP; a server that breaks 0x20 is asked in lower case, a server that is lame for a zone is skipped for it. Tests in `crates/tenko-dns/src/recurse/net/tests.rs` (`no_answer_is_a_timeout_within_the_deadline`, `formerr_without_opt_to_an_edns_query_is_asked_again_without_edns`, `an_answer_whose_question_comes_back_in_another_case_is_a_0x20_failure`), `crates/tenko-dns/src/recurse/tests.rs` (the cases of `CASES`), the lab rows `rec.0x20`, `rec.formerr`, `rec.tc`, `rec.lame`, `rec.slow` |
| 8914 | Extended DNS Errors | DNS | 2 | Planned | DNS-21 | Used for blocked and filtered responses and for DNSSEC failures |
| 8945 | Secret Key Transaction Authentication for DNS (TSIG) | DNS | 2 | Planned | DNS-09, DNS-11 | |
| 9018 | Interoperable Domain Name System (DNS) Server Cookies | DNS | 2 (server cookies), 5 (cookies to authorities) | Implemented | DNS-03 | The server cookie the engine hands out since Phase 2 is the one of section 4 (SipHash-2-4, version 1, `crates/tenko-dns/src/cookie.rs`). Towards authorities (WP10.1) the client cookie is the SipHash-2-4 of the server's address under a secret the engine draws at start and does not change while it runs (section 3), and the server cookie that comes back is kept per server in the infrastructure cache (`crates/tenko-dns/src/infra.rs`) and sent from then on. Tests in `crates/tenko-dns/src/recurse/tests.rs` (`cookies_are_per_server_and_the_extended_error_goes_into_the_opt_record`), `crates/tenko-dns/src/recurse/net/tests.rs` (`a_plain_exchange_answers_over_udp_with_edns_and_returns_the_server_cookie`, `build_carries_the_server_cookie_after_the_client_cookie`), `crates/tenko-dns/src/cookie.rs` |
| 9103 | DNS Zone Transfer over TLS | DNS | 2 | Planned | DNS-09 | XoT |
| 9156 | DNS Query Name Minimisation to Improve Privacy | DNS | 5 | Planned | DNS-34 | |
| 9210 | DNS Transport over TCP: Operational Requirements | DNS | 5 | Partial | DNS-03 | TCP to authorities on a truncated answer and for servers marked TCP-only (after three truncated answers in a row, or over 1,000 unwanted answers in an hour, for the rest of the hour). Not done: connection reuse, keepalive (RFC 7828) and the management of idle connections, since each exchange opens its own connection. Tests in `crates/tenko-dns/src/recurse/net/tests.rs` (`a_truncated_udp_answer_is_followed_over_tcp`, `a_query_that_asks_for_tcp_goes_straight_to_tcp`), `crates/tenko-dns/src/infra/servers.rs` (`times_back_off_and_case_follow_the_pool`, `unwanted_answers_force_tcp_and_flag_a_flush`), `crates/tenko-dns/src/recurse/tests.rs` (`the_ladder_and_the_bailiwick_leave_their_marks_in_the_caches`), the lab rows `rec.tc` and `rec.big` |
| 9250 | DNS over Dedicated QUIC Connections | DNS | 5 | Planned | DNS-16 | DoQ |
| 9276 | Guidance for NSEC3 Parameter Settings | DNS | 5 | Planned | DNS-13 | The validator treats a zone whose NSEC3 iterations exceed the cap as insecure; the signer has followed the guidance since Phase 2 (ADR 0018 point 5) |
| 9293 | Transmission Control Protocol | Other | 1 | Partial | SCAN-04 | Current TCP specification; the `tcp_syn` scan reads and builds only the SYN handshake and RST (see RFC 793). Tests in `crates/tenko-scan/src/frame/tcp.rs` |
| 9432 | DNS Catalog Zones | DNS | 2 | Planned | DNS-10 | |
| 9471 | DNS Glue Requirements in Referral Responses | DNS | 5 | Partial | DNS-03 | The resolver's side: in-domain glue is cached and used, sibling glue is used for the step and marked `sibling_glue`, and every other address in the additional section is ignored (a glue address outside the bailiwick is never cached or asked). Not done: sibling glue is not held back until the resolver has confirmed it from the glue's own authority; it is used as any glue and stays marked until a lookup of the name replaces it. Tests in `crates/tenko-dns/src/recurse/message/tests.rs` (`a_referral_keeps_in_domain_glue_with_the_smallest_ns_ttl`, `a_referral_marks_glue_from_a_sibling_zone_as_sibling`, `a_referral_drops_glue_out_of_bailiwick_and_glue_for_names_it_does_not_delegate_to`), `crates/tenko-dns/src/recurse/tests.rs` (the out-of-bailiwick case of `CASES`, `the_ladder_and_the_bailiwick_leave_their_marks_in_the_caches`), fuzz target `dns_referral`, the lab row `rec.oob` |
| 9520 | Negative Caching of DNS Resolution Failures | DNS | 5 | Partial | DNS-03 | Resolution failures cached for 5 s, doubling on a repeat up to `failure_cache_max_secs` (300), and answered SERVFAIL with the same extended error without a query to an authority; a cap on the work per client query (32 queries, 8 links, 3 attempts per server, 10 s). The cache of WP10.1 is the in-memory reference of the recursion contracts (`MemFailures`): it has no bound, never drops an expired entry from memory and is not emptied by the cache flush; the bounded cache with the lookup on the worker is WP10.3. Tests in `crates/tenko-dns/src/recursion/tests.rs` (`failures_hold_five_seconds_doubling_to_the_bound`), `crates/tenko-dns/src/recurse/tests.rs` (`every_case_of_e36_ends_within_the_budget_with_its_query_count`, which asks each failing case twice), the lab cases with SERVFAIL, which ask twice |
| 9539 | Unilateral Opportunistic Deployment of Encrypted Recursive-to-Authoritative DNS | DNS | 5 | Planned | DNS-03 | A later decision ([dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q14); the transport hook is named |
| 9558 | Use of GOST 2012 Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC | DNS | n/a | Deliberately skipped | DNS-13 | Algorithm 23 is MAY for validation in RFC 8624's successors and is not provided by the crypto in use; zones signed with it alone are insecure |

## Superseded RFCs

Tenko tracks conformance against the replacing RFC only.

| Obsoleted RFC | Replaced by | Note |
|---|---|---|
| 2671 | 6891 | EDNS(0) |
| 2845 | 8945 | TSIG |
| 3315 | 8415 | DHCPv6 |
| 3633 | 8415 | Prefix delegation folded into DHCPv6 |
| 5966 | 7766 | DNS transport over TCP |
| 7816 | 9156 | QNAME minimization, experimental version |

## Other specifications

Standards and de facto behaviors outside the RFC series that Tenko depends on, implements, or deliberately skips.

| Spec | Area | Target phase | Status | Requirements | Notes |
|---|---|---|---|---|---|
| DNS Response Policy Zones (RPZ), draft-vixie-dnsop-dns-rpz | DNS | 2 | Planned | DNS-21 | |
| dnstap | DNS | 2 | Planned | DNS-26 | |
| DHCPv4 failover | DHCP | 3 | Planned | DHCP-12, CON-05 | No RFC exists; Tenko uses its own partner protocol between Tenko nodes only; Windows and ISC failover are proprietary and not interoperable, so coexistence uses split scopes |
| Preboot Execution Environment (PXE) Specification 2.1 (Intel) | DHCP | 3 | Planned | DHCP-05 | Boot-server discovery and ProxyDHCP on port 4011 (plan P3-Q16) |
| UEFI HTTP Boot (UEFI Specification) | DHCP | 3 | Planned | DHCP-05 | Vendor class `HTTPClient`, the boot URL in the file field |
| Active Directory DC locator DNS records (`_msdcs`, `_sites` SRV) | DNS | 4 | Planned | DNS-30 | |
| Windows DNS aging and scavenging semantics | DNS | 4 | Planned | DNS-29 | |
| Windows Global Query Block List and GlobalNames zone | DNS | 4 | Planned | DNS-31, DNS-32 | |
| WINS and WINS-R lookup (Windows DNS extension) | DNS | n/a | Deliberately skipped | CON-12 | |
| IEEE 802.1AB (LLDP) | Other | 1 | Partial | SCAN-02, SCAN-05 | The passive `lldp` method parses the mandatory and the common optional TLVs (chassis id, port id, TTL, port description, system name and description, capabilities, management address, 802.1 PVID and VLAN name); Tenko does not transmit LLDP. Tests in `crates/tenko-scan/src/frame/lldp.rs` |
| Cisco Discovery Protocol (CDP) version 2 | Other | 1 | Partial | SCAN-02, SCAN-05 | The passive `lldp` method also parses CDP v2 (device id, addresses, port id, capabilities, software version, platform, native VLAN); Tenko does not transmit CDP. Tests in `crates/tenko-scan/src/frame/cdp.rs` |
| W3C Web Authentication (WebAuthn, passkeys) | Other | 1 | Planned | IAM-06 | |
| NIST SP 800-63B (password semantics) | Other | 1 | Planned | IAM-03 | |
| OpenMetrics | Other | 1 | Planned | OPS-05 | |
| IANA root hints (`named.root`) and root zone trust anchors (`root-anchors.xml`, RFC 7958), with the KSK rollover schedule ICANN publishes | DNS | 5 | Planned | DNS-03, DNS-13 | Both shipped in the binary and refreshed by priming (hints) and RFC 5011 (anchors); [dns-recursion-plan.md](plans/dns-recursion-plan.md) REC-Q6 and REC-Q7 |
| DNS flag day 2019 (no fallback to queries without EDNS) and 2020 (UDP payload 1232) | DNS | 5 | Planned | DNS-03 | The resolver's queries to authorities; the served side follows them since Phase 2 (RFC 6891 row) |

## Test data conventions

All addresses and names in test data, fixtures and documentation examples come from ranges reserved for documentation, so that no test can touch a real host.

| RFC | Use |
|---|---|
| RFC 5737 | IPv4 documentation blocks 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 for all IPv4 addresses |
| RFC 3849 | IPv6 documentation prefix 2001:db8::/32 for all IPv6 addresses |
| RFC 7042 | Documentation MAC range 00-00-5E-00-53-00 to 00-00-5E-00-53-FF for all MAC addresses |
| RFC 2606 | Reserved domain names (`example.com`, `.test`, `.example`, `.invalid`) for all DNS names |
