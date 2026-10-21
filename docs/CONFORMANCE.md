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
| 1034 | Domain Names: Concepts and Facilities | DNS | 2 | Planned | DNS-01 | |
| 1035 | Domain Names: Implementation and Specification | DNS | 2 | Planned | DNS-01, MIG-15 | Zone file format also used for import and export |
| 1123 | Requirements for Internet Hosts: Application and Support | DNS | 2 | Planned | DNS-05 | |
| 1918 | Address Allocation for Private Internets | Other | 1 | Planned | IPAM-01 | Overlapping private space handled with tenants and VRFs |
| 1995 | Incremental Zone Transfer in DNS | DNS | 2 | Planned | DNS-09 | |
| 1996 | A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY) | DNS | 2 | Planned | DNS-09 | |
| 2131 | Dynamic Host Configuration Protocol | DHCP | 3 | Planned | DHCP-01 | |
| 2132 | DHCP Options and BOOTP Vendor Extensions | DHCP | 3 | Planned | DHCP-02, DHCP-15 | Includes option 6 (DNS servers) and option 42 (NTP) |
| 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | DNS | 2 | Planned | DNS-11, CONN-13 | |
| 2308 | Negative Caching of DNS Queries (DNS NCACHE) | DNS | 2 | Planned | DNS-02 | |
| 2317 | Classless IN-ADDR.ARPA delegation | DNS | 2 | Planned | DNS-22 | Automatic reverse zones from IPAM for shared /24s |
| 3004 | The User Class Option for DHCP | DHCP | 3 | Planned | DHCP-03 | |
| 3011 | The IPv4 Subnet Selection Option for DHCP | DHCP | 3 | Planned | DHCP-04 | Option 118; scope selection before giaddr |
| 3046 | DHCP Relay Agent Information Option | DHCP | 3 | Planned | DHCP-04 | Option 82, circuit-id and remote-id |
| 3074 | DHC Load Balancing Algorithm | DHCP | 3 | Planned | DHCP-12 | Hash split between failover partners |
| 3203 | DHCP reconfigure extension | DHCP | n/a | Deliberately skipped | CON-10 | FORCERENEW is not supported by clients in practice; move jobs wait for observation instead |
| 3396 | Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4) | DHCP | 3 | Planned | DHCP-02 | Options longer than 255 octets split and concatenated |
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
| 4578 | Dynamic Host Configuration Protocol (DHCP) Options for the Intel Preboot eXecution Environment (PXE) | DHCP | 3 | Planned | DHCP-05 | Option 93 client architecture |
| 4701 | A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR) | DHCP | 3 | Planned | DHCP-13 | |
| 4702 | The Dynamic Host Configuration Protocol (DHCP) Client Fully Qualified Domain Name (FQDN) Option | DHCP | 3 | Planned | DHCP-13 | Option 81 |
| 4703 | Resolution of Fully Qualified Domain Name (FQDN) Conflicts among Dynamic Host Configuration Protocol (DHCP) Clients | DHCP | 3 | Planned | DHCP-13 | Name protection |
| 4704 | The Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Client Fully Qualified Domain Name (FQDN) Option | DHCP | 3 | Planned | DHCP-13 | |
| 4795 | Link-local Multicast Name Resolution (LLMNR) | Other | 1 | Partial | SCAN-03 | Unicast reverse queries to known addresses, answers read from recorded responses in `crates/tenko-scan/tests/`. Tenko is not a responder and does not listen |
| 4861 | Neighbor Discovery for IP version 6 (IPv6) | Other | 1 (discovery), 3 (RA interplay) | Planned | SCAN-02, DHCP-10 | Passive ND discovery; M/O flag interplay with DHCPv6, which cannot set a default route |
| 5011 | Automated Updates of DNS Security (DNSSEC) Trust Anchors | DNS | 5 | Planned | DNS-13 | |
| 5071 | Dynamic Host Configuration Protocol Options Used by PXELINUX | DHCP | 3 | Planned | DHCP-05 | |
| 5107 | DHCP Server Identifier Override Suboption | DHCP | 3 | Planned | DHCP-04 | |
| 5155 | DNS Security (DNSSEC) Hashed Authenticated Denial of Existence | DNS | 2 | Planned | DNS-12 | NSEC3 |
| 5424 | The Syslog Protocol | Other | 1 | Planned | IAM-18 | Audit export |
| 5908 | Network Time Protocol (NTP) Server Option for DHCPv6 | DHCP | 3 | Planned | DHCP-09, DHCP-15 | Option 56 |
| 6238 | TOTP: Time-Based One-Time Password Algorithm | Other | 1 | Planned | IAM-06 | |
| 6762 | Multicast DNS | Other | 1 | Partial | SCAN-02 | Queries from an ephemeral port (legacy unicast responses), unicast reverse queries to known addresses, and optional listening on a shared port 5353 during the run window. Tenko is not an mDNS responder. Answers read from recorded responses in `crates/tenko-scan/tests/` |
| 6763 | DNS-Based Service Discovery | Other | 1 | Partial | SCAN-02 | Browsing of service types, and reading of PTR, SRV and TXT records for TCP ports and OS hints. No service registration or announcing |
| 6842 | Client Identifier Option in DHCP Server Replies | DHCP | 3 | Planned | DHCP-01 | Option 61 echoed |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | DNS | 2 | Planned | DNS-06 | Default UDP buffer size 1232 |
| 6939 | Client Link-Layer Address Option in DHCPv6 | DHCP | 3 | Planned | DHCP-11 | |
| 7344 | Automating DNSSEC Delegation Trust Maintenance | DNS | 2 | Planned | DNS-12 | CDS and CDNSKEY |
| 7766 | DNS Transport over TCP: Implementation Requirements | DNS | 2 | Planned | DNS-05 | TCP is mandatory |
| 7858 | Specification for DNS over Transport Layer Security (TLS) | DNS | 2 | Planned | DNS-14, DNS-15 | |
| 7860 | HMAC-SHA-2 Authentication Protocols in User-Based Security Model (USM) for SNMPv3 | Other | 1 | Partial | SCAN-05 | HMAC-SHA-224, -256, -384 and -512 with the digest lengths of the RFC. Keys and digests checked against independent values in `crates/tenko-scan/src/snmp/` |
| 7871 | Client Subnet in DNS Queries | DNS | 5 | Planned | DNS-03 | Scope to be decided; privacy implications (OPS-06); not used for view matching, which uses the query source |
| 7873 | Domain Name System (DNS) Cookies | DNS | 2 | Planned | DNS-07 | |
| 7969 | Customizing DHCP Configuration on the Basis of Network Topology | DHCP | 3 | Planned | DHCP-04 | Scope selection from relay information, link selection and the DHCPv6 link address |
| 8078 | Managing DS Records from the Parent via CDS/CDNSKEY | DNS | 2 | Planned | DNS-12 | |
| 8156 | DHCPv6 Failover Protocol | DHCP | 3 | Planned | DHCP-12 | |
| 8198 | Aggressive Use of DNSSEC-Validated Cache | DNS | 5 | Planned | DNS-34 | |
| 8415 | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) | DHCP | 3 | Planned | DHCP-09 | IA_NA, IA_PD, DUID, relay |
| 8482 | Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY | DNS | 2 | Planned | DNS-18 | |
| 8484 | DNS Queries over HTTPS (DoH) | DNS | 2 | Planned | DNS-14, DNS-15 | |
| 8767 | Serving Stale Data to Improve DNS Resiliency | DNS | 2 | Planned | DNS-23 | |
| 8914 | Extended DNS Errors | DNS | 2 | Planned | DNS-21 | Used for blocked and filtered responses and for DNSSEC failures |
| 8945 | Secret Key Transaction Authentication for DNS (TSIG) | DNS | 2 | Planned | DNS-09, DNS-11 | |
| 9103 | DNS Zone Transfer over TLS | DNS | 2 | Planned | DNS-09 | XoT |
| 9156 | DNS Query Name Minimisation to Improve Privacy | DNS | 5 | Planned | DNS-34 | |
| 9250 | DNS over Dedicated QUIC Connections | DNS | 5 | Planned | DNS-16 | DoQ |
| 9432 | DNS Catalog Zones | DNS | 2 | Planned | DNS-10 | |

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
| IEEE 802.1AB (LLDP) | Other | 1 | Planned | SCAN-02, SCAN-05 | |
| W3C Web Authentication (WebAuthn, passkeys) | Other | 1 | Planned | IAM-06 | |
| NIST SP 800-63B (password semantics) | Other | 1 | Planned | IAM-03 | |
| OpenMetrics | Other | 1 | Planned | OPS-05 | |

## Test data conventions

All addresses and names in test data, fixtures and documentation examples come from ranges reserved for documentation, so that no test can touch a real host.

| RFC | Use |
|---|---|
| RFC 5737 | IPv4 documentation blocks 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 for all IPv4 addresses |
| RFC 3849 | IPv6 documentation prefix 2001:db8::/32 for all IPv6 addresses |
| RFC 7042 | Documentation MAC range 00-00-5E-00-53-00 to 00-00-5E-00-53-FF for all MAC addresses |
| RFC 2606 | Reserved domain names (`example.com`, `.test`, `.example`, `.invalid`) for all DNS names |
