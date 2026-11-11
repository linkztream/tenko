# Service discovery plan: an mDNS gateway between segments and a Discovery Proxy

- Status: Draft, waiting for the owner's decisions (SD-Q1 to SD-Q14 of section 6); no package starts before the owner says so
- Date: 2026-11-11
- Scope: DNS-35, added by the owner on 2026-11-10. Service discovery across network segments, off by default and governed by a policy per service type and per ordered pair of networks, in two parts that can be built one after the other: (a) an mDNS gateway on the probes, (b) a Discovery Proxy served by Tenko's DNS server. Written against `main` at `cbe6c27a`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md). Exit criteria, measurements and risks continue the project's series: E100 onward, M77 onward and R175 onward (the public DNS plan ends at E88, M72 and R159; the notifications plan takes E89 to E99, M73 to M76 and R160 to R174)

This plan follows the shape of [public-dns-plan.md](public-dns-plan.md): the goal and the exit criteria as checks, the design decisions the packages share, the contracts, the work packages with owned files, the order, the owner's decisions, the risks and the owner's actions. "(proposed)" marks a choice the documents leave open. Sizes are in builder-days. One record needs an ADR (the lead numbers it; this plan proposes 0037, since the public DNS plan proposes 0035 and the notifications plan 0036); section 3.6 names what it must decide. The slice number is the lead's; this plan calls it Slice 17 and its packages WP17.0 to WP17.6.

Every statement about a standard was read on the RFC pages of section 11 on 2026-11-11. A statement marked **(unconfirmed)** could not be confirmed there and is checked by the package named before any text or code relies on it.

**Terms used throughout.** *mDNS* (multicast DNS, RFC 6762) is DNS without a server: a device asks and answers on its own link by UDP multicast to `224.0.0.251` and `ff02::fb`, port 5353, for names under `.local`. *DNS-SD* (DNS-based service discovery, RFC 6763) is a convention for finding services with ordinary record types: a PTR record (pointer) lists the instances of a service type (`_ipp._tcp.local` lists printers), an SRV record (service locator) gives an instance's host name and port, a TXT record (text) carries key=value attributes, and A and AAAA records give the host's IPv4 and IPv6 addresses. An NSEC record (next secure) states which types a name has, so that a querier knows the others do not exist. A *link* is one layer-2 segment, the set of hosts that reach each other without a router; a *VLAN* (virtual LAN) is a separate layer-2 segment on shared switches, so each VLAN is a link. A *repeater* (or *reflector*) is a program on a host with interfaces on several links that copies mDNS packets from one link to the others. *IP TTL* (time to live, in IPv6 the hop limit) is the counter in the IP header that every router lowers by one; a DNS record's *TTL* is the number of seconds a cache may keep it, a different thing. *Probing* (RFC 6762 section 8) is the check a responder makes that a name is free before it uses it; it is unrelated to Tenko's *probe*, the node role that observes a segment (SCAN-01).

**Further terms**, in the order they appear. An *ADR* (architecture decision record) is a numbered document under `docs/adr/` that records one design decision. In a DNS message header the *QR bit* says whether the message is a query or a response, and the *TC bit* (truncated) says that more follows; in mDNS a query with TC set continues its list of known answers in the next packet. An *SOA* record (start of authority) opens a zone and carries its timers; *NS* records (name server) name the servers of a zone, and NS records in the parent zone *delegate* a subzone; an *RRset* is all records of one name and type. *EDNS* (extension mechanisms for DNS) lets a client announce a larger UDP answer size. *DNSSEC* (DNS security extensions) signs zones; *TLS* (transport layer security) encrypts a connection. *ARP* (address resolution protocol) and its IPv6 counterpart neighbor discovery map an address to a MAC address on a link. *IPP* (Internet Printing Protocol) is the printing protocol behind most network printers; *IANA* (Internet Assigned Numbers Authority) assigns port numbers. *Punycode* is the ASCII encoding of non-ASCII names in DNS. *Matter* is a home-automation standard whose devices are found by DNS-SD; *Thread* is a low-power wireless mesh network, joined to the IP network by a *border router* that announces the devices behind it. A *sleep proxy* answers mDNS for a computer that sleeps. *NAT* (network address translation) rewrites addresses at a router; *UPnP*, *NAT-PMP* and *PCP* are protocols with which a program asks a router to open a port. *p99* is the value below which 99 percent of the samples lie. A *property test* checks a rule against many generated inputs; a *fuzz target* feeds a parser random and mutated input to find crashes (CONTRIBUTING rule 3).

Contents:

1. [Scope and exit](#1-scope-and-exit)
2. [Design decisions the packages share](#2-design-decisions-the-packages-share)
3. [Contracts and shared files (WP17.0)](#3-contracts-and-shared-files-wp170)
4. [Work packages](#4-work-packages)
5. [Order, measurements and exit checks](#5-order-measurements-and-exit-checks)
6. [Owner decisions](#6-owner-decisions)
7. [Requirement rows touched](#7-requirement-rows-touched)
8. [Risks](#8-risks)
9. [Owner actions and the check list with real devices](#9-owner-actions-and-the-check-list-with-real-devices)
10. [Documents this slice writes](#10-documents-this-slice-writes)
11. [Sources](#11-sources)

## 1. Scope and exit

### 1.1 Goal

**The case this is for.** A home or small-office network with several VLANs behind one gateway and firewall: in this plan a trusted segment `lan` (`192.0.2.0/26`, `2001:db8:10::/64`) for computers and phones, and a segment `iot` (`192.0.2.64/26`, `2001:db8:11::/64`) for devices that are not trusted: casting devices (a receiver that plays what a phone sends it), a printer, home-automation devices. A phone on `lan` must find the casting device and the printer on `iot`, and must not open the two segments to each other to do it. Most such devices and their apps discover only by mDNS on their own link: a phone on `lan` never sees an announcement made on `iot`. Today the usual answer is the firewall's own "mDNS repeater", which copies every mDNS packet between the chosen interfaces.

**What a plain repeater does, and what this slice does instead.**

| Concern | A plain repeater (the small repeater daemon, or Avahi's reflector) | Tenko's gateway |
|---|---|---|
| What crosses | Every mDNS packet, every service type, every device, both directions; Avahi's reflector can filter by service type or machine name (`reflect-filters`), the small repeater cannot | Only the service types and devices a rule names, and only in the direction of the rule's ordered pair (`iot` to `lan` does not imply `lan` to `iot`) |
| What is carried | The packet, re-sent from the repeater's address | Validated, normalized records, never a packet; the packet is rebuilt on the other link |
| Who answers for the records | Nobody: the copies claim to be on the link and the original device cannot defend them | The gateway, as a proxy responder: it probes, announces, answers, and sends goodbyes for what it carries (section 2.4) |
| A device on `iot` that claims a name of a device on `lan` | Its copy reaches `lan`; the device on `lan` may lose its name at its next probing and rename itself | The device on `lan` always wins; the gateway never defends a carried name and yields at once (section 2.4) |
| A device that points a service at someone else's address | Copied | Not carried unless its address records are on its own link and include its own source address (section 2.3) |
| Floods | Copied, at the speed of the flood | Bounded per device, per link and per pair, with numbers (section 2.8) |
| Loops | Two repeaters between the same links, or a bridge, can echo packets | No record is carried back to its origin link; records heard from a non-device source are not originated (section 2.7) |
| What a phone announces about itself | Copied to the untrusted segment | Not carried unless a rule names it |
| What the operator sees | Nothing | A learn mode that shows what each link announces before anything crosses, the services on each device's host view, the flows the firewall must allow, findings and audit records |
| Clients that browse by unicast DNS | Not served | The Discovery Proxy serves them from the same service table (part b) |

**What changes.**

1. **Links.** The operator binds a probe's interface to one or more IPAM networks (prefixes): that pair of probe and interface is a link.
2. **Learn mode.** Per link, the probe listens continuously and the UI shows every service type, instance and device announced there; nothing crosses.
3. **Rules.** A rule names a service type, an ordered pair of links (from, to), and the devices whose announcements may cross. Only rules make anything cross.
4. **The gateway (part a).** The probe on the source link reports the announcements a rule selects; the controller checks them against the rules and hands them to the probe on the destination link, which announces them there as a proxy from its own address and answers questions for them; questions asked on the destination link reach the source link as fresh queries made by its probe.
5. **The Discovery Proxy (part b).** The same records are served by Tenko's DNS server as unicast DNS-SD under a subdomain per link (for example `iot.sd.example.test`), with the browsing domains that let clients find those subdomains.
6. **The host view** shows the services each device announces and where they cross. **The firewall view** lists the unicast flows a client needs to use what it discovered, and can test whether they pass; Tenko never changes a firewall.

**What stays.** Nothing is bridged at layer 2 and no multicast packet crosses a link. The probes keep their role (SCAN-01, SCAN-02) and their systemd grant (section 2.16). The DNS server's query path stays memory-only (ADR 0009 decision 5, ADR 0017 decision 2). The function is off by default in every profile, and with no rule nothing crosses.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E100 | The mDNS codec: every fixture of `crates/tenko-scan/tests/fixtures/` decodes; a decode followed by an encode gives an equal message (property test); the top bit of the class field is read and written as the unicast-response bit in questions and the cache-flush bit in records; NSEC decodes and encodes with its type bitmap; a known-answer list spread over several packets with the TC bit is joined; a message over 9,000 bytes, a pointer loop and a forward pointer are refused; the fuzz target `mdns_message` runs in the weekly smoke | DNS-35, SCAN-02 | WP17.1 |
| E101 | The link listener: on a host with two interfaces (the lab), a packet is attributed to the interface it arrived on, IPv4 and IPv6; a packet whose source address is outside the link's prefixes and is not link-local is dropped; the probe's own packets are ignored; the probe's systemd hardening score does not move (`deploy/systemd/check-hardening.sh`) | DNS-35, SCAN-01 | WP17.1 |
| E102 | The policy: nothing crosses without a rule (property test over random announcements, links and rules); a rule `iot` to `lan` carries nothing from `lan` to `iot`; learn mode carries nothing; a device outside a rule's list does not cross; an event of a probe that names a link of another node is refused; a carried name that the destination link has used within 30 days, or that contains bidirectional or invisible format characters, is refused; under Hardened a rule without a device list, or created without the step-up, is refused; one audit record per rule change | DNS-35, TGL-24 | WP17.2 |
| E103 | The gateway on the wire (lab): a printer service published on `iot` is found by a browser on `lan` within 2 s of the rule; the packets on `lan`, multicast and unicast answers alike, come from the `lan` probe's address with IP TTL 255 from port 5353; unique records carry the cache-flush bit after probing and the PTR does not; a query on `lan` that lists the record with at least half its TTL gets no answer (known-answer suppression); a goodbye on `iot` gives a goodbye on `lan` within 1 s; deleting the rule sends goodbyes for everything it carried | DNS-35 | WP17.3 |
| E104 | Names: a host on `lan` that claims a carried name keeps it: the gateway never answers its probes, withdraws the carried records within 1 s of its announcement and raises `sd.conflict`; in a capture of the whole round, no host on `lan` renames itself | DNS-35 | WP17.3 |
| E105 | Loops: rules in both directions between `lan` and `iot` plus an Avahi reflector on a third host joined to both networks: no record is carried back to its origin link, the packet rate on each network stays under the bounds of section 2.8 for 10 minutes, and `sd.repeater_detected` is raised | DNS-35 | WP17.3, WP17.6 |
| E106 | Floods and lies: a generator on `iot` sends 1,000 instances, 200 packets per second, TXT records of 2,000 bytes, address records outside its link and announcements for another device's address: the same from 10,000 spoofed IPv6 source addresses of one `/64`: the generator is muted with `sd.flood`, nothing beyond the bounds crosses, the devices the rules select keep crossing, the limiter's state stays within its bound, and the probe stays under M77's memory bound | DNS-35 | WP17.1, WP17.3, WP17.6 |
| E107 | The controller unreachable: with the controller stopped, nothing new crosses, the carried records expire at their own TTL and no goodbye is sent; with it back, the carried set is complete again within 10 s; a probe stopped with SIGTERM sends goodbyes for what it carried | DNS-35 | WP17.3 |
| E108 | The Discovery Proxy: from a client on `lan`, `dig PTR _ipp._tcp.iot.sd.example.test` lists the printer, and its SRV, TXT, A and AAAA answer with TTL 10; the SOA of the subdomain has the values of RFC 8766 section 6.1, and the parent zone delegates the subdomain (NS, no DS) in its answers and its transfers; link-local addresses are never in an answer; a client on `iot` or on a third network is refused; `b`, `db` and `lb` under `_dns-sd._udp.example.test` and the address-derived `lb` name of the client's prefix list the subdomain; a unicast browser (Avahi with `browse-domains`) finds the printer; every name of RFC 8766 sections 6.3 and 6.4 (section 2.10) answers at once that it does not exist; random names asked at 100 per second cause at most the bounded interests of section 2.8 | DNS-35, DNS-20 | WP17.4 |
| E109 | The host view: a carried and a learned service appear on the device's host view with type, instance, port and the links it crosses to; no TXT value is in the store outside `sd.services` (a scan of the store's bytes in the test) | DNS-35, IPAM-12 | WP17.2, WP17.5 |
| E110 | The UI: links, learn mode, rules with the device list, the services that cross, the flows and their test; Playwright tests over the mock | DNS-35 | WP17.5 |
| E111 | The security rows `sd.*` of section 4 pass on the release binary | DNS-35 | WP17.6 |
| E112 | The owner's check list of section 9.2 with real devices, recorded without real names | DNS-35 | WP17.6 (owner-run) |
| E113 | The flow test (lab): with the router allowing TCP 631 to the printer and dropping the receiver's port, the test from `probe-lan` reports *reachable* for the first and *no answer* with `sd.flow_blocked` for the second; a second test within the hour is refused; one audit record per test; no packet from Tenko reaches the router's own addresses | DNS-35, SCAN-04 | WP17.1, WP17.2, WP17.6 |

**The trace.** `scripts/requirement-trace.mjs` reads exit criteria as `E` and one or two digits (its lines 216, 286 and 323), so E100 onward is not traced until the script accepts three digits; WP17.0 widens the pattern when this plan joins the Phase 4 list of the script (section 10).

### 1.3 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| DNS-35 Service discovery across network segments | All of it | 4, Must |
| SCAN-01 One probe per network segment | Unchanged; a probe may serve more than one link (SD-Q6) | 1, delivered |
| SCAN-02 Passive discovery first (mDNS among them) | The passive mDNS listener moves onto the link listener of section 2.3 and gains IPv6 and per-interface reception | 1, delivered |
| IPAM-12 Intent and observation | A new observation kind, the announced service (section 2.12) | 1, delivered |
| IPAM-21 The reconciliation view | Not changed; services are shown on the host view | 3, delivered |
| DNS-20 Views | The Discovery Proxy's subdomains answer only the clients the rules allow (section 2.10); no view is added by hand | 2, delivered |
| OPS-06 Personal data in logs | Applied to service instance names, which can carry a person's name (section 2.12) | 2, delivered |
| SCAN-04, TGL-18 Active probing | The reachability test of section 2.13 is active probing and follows TGL-18 | 1, delivered |

### 1.4 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| DNS Push (RFC 8765) and Long-Lived Queries (RFC 8764) | SD-Q8: Push needs DNS Stateful Operations (RFC 8490) over TLS, a long-lived session path the DNS server does not have; RFC 8766 section 5.6 expects LLQ to be retired; the clients that use them still work with ordinary queries | A later slice, with DSO |
| The reverse-mapping zones of RFC 8766 section 5.4 (answers for `in-addr.arpa` and `ip6.arpa` names by multicast queries on the link) | Tenko's reverse zones already answer for every address IPAM knows; a reverse name generated from mDNS would compete with them | Not planned |
| DNSSEC signing of the Discovery Proxy's subdomains (RFC 8766 section 7, online signing) | The subdomains are internal and short-lived (TTL 10 s); TGL-13 asks for signing of zones served externally only | Later, if an internal validating client needs it |
| Service registration by clients (SRP, RFC 9665) and the Advertising Proxy (an Internet-Draft) | A different trust model (signed registrations), and the Advertising Proxy is not an RFC | Later, if Thread border routers make it worth it |
| Renaming carried services (a suffix per link) | SD-Q2: identities of some protocols live in the instance name (Matter's operational names encode the fabric and the node) | Not planned |
| Answering the browsing names under `.local` on the link (`b._dns-sd._udp.local` and `lb._dns-sd._udp.local`, RFC 8766 section 5.2.2, a MAY) | Clients find the subdomains by unicast DNS already (section 2.10); answering on the link would make the probe an mDNS responder for a second kind of name | Later, if a client is found that needs it |
| Carrying across sites (WAN) | Same design, but latency and the controller's reach are not measured here; no requirement asks for it | Phase 5 measurement |
| The gateway on a Windows probe | The probe's sockets per interface and its systemd grant are Linux facts; the Windows probe keeps its scanner | Later, on request |
| A firewall connector that writes rules, UPnP, NAT-PMP or PCP port openings | Tenko never changes a firewall (section 2.13) | Never |

### 1.5 Starting point in the code

Facts the packages build on, read on `cbe6c27a` (nothing was run):

- **The probe role** (SCAN-01, SCAN-02, [cluster.md](../cluster.md)): a probe is a node enrolled with a single-use token for the role `probe` (and an optional VRF, a virtual routing and forwarding table), placed on a host in the segment, connecting out to the controller on 8444/TCP over mTLS (mutual TLS: both sides present certificates of the internal CA). A probe has no link to an IPAM prefix: its scope is the CIDR (address range) list `ScanConfig.prefixes` of its scan configuration (`crates/tenko-scan/src/config.rs`), held per node as `ProbeConfigRecord` (`crates/tenko-scan/src/control/model.rs`).
- **mDNS in the scanner** (`crates/tenko-scan/src/methods/names.rs`, `crates/tenko-scan/src/dns/`): queries are sent from an ephemeral port (so answers come back as legacy unicast), to `224.0.0.251` only; a passive listener binds `0.0.0.0:5353` with `SO_REUSEADDR` and `SO_REUSEPORT` and joins `224.0.0.251` on the default interface only, during the run window (`listen_secs`, default 4) of each run; there is no IPv6 join and no per-interface socket. Tenko never announces or answers (docs/scanning.md section 2.5). Findings land as `address`, `name`, `services` (open TCP ports from SRV records) and `os` facts under the source `probe:<node>:mdns`; service types, instance names and TXT values are not kept.
- **The scanner's DNS parser** (`crates/tenko-scan/src/dns/message.rs`) is written on the `domain` crate (0.12.3, the codec ADR 0009 chose), with bounds (9,000 bytes, 256 records, 32 questions, 64 TXT strings); it masks the class field's top bit and records `cache_flush`, sets the unicast-response bit on the queries it builds, and reads all sections of queries and responses. It is lossy: record data is typed as A, AAAA, PTR, SRV, TXT, HINFO or `Other(type)` without its bytes, NSEC is not read, and nothing encodes answers. Its fuzz target is `fuzz/fuzz_targets/scan_dns_message.rs`; recorded packets are hex fixtures in `crates/tenko-scan/tests/fixtures/dns/` (`mdns_printer.hex`, `mdns_query_qu.hex`, `mdns_services_browse.hex` and others).
- **The server's codec** (`crates/tenko-dns/src/codec/`) parses single-question queries only and refuses a message with the QR bit set, so it cannot read mDNS traffic; it answers only class IN (`authoritative.rs`, `early()`), and keeps record data as opaque wire bytes. `tenko-scan` and `tenko-dns` do not depend on each other.
- **Node sync** ([node-sync.md](../node-sync.md), `crates/tenko-cluster/proto/tenko/cluster/v1/`): upward, `Observations.Ingest` carries sightings (`PROBE_METHOD_MDNS` among the methods), `Config.Report` the applied revision and the probe's scope; downward, `Config.Watch` streams the node's configuration (kept in `state.cbor`, used across restarts and outages), and `Commands.Subscribe` streams commands (`scan.run`, `scan.cancel`, `scan.stop`, `scan.resume`). There is no probe-to-probe path and no message that carries records to announce.
- **The probe's systemd grant** (`deploy/systemd/probe.conf`): `CAP_NET_BIND_SERVICE CAP_NET_RAW`, address families `AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET`; the base unit runs as `tenko` with `CAP_NET_BIND_SERVICE` only. Port 5353 is unprivileged. ADR 0023: no root after installation, capabilities are granted per role at installation, a new capability is a host reconfiguration. The DHCP server already binds sockets to an interface with `SO_BINDTODEVICE` through `socket2` (`crates/tenko-dhcp/src/server/socket.rs`).
- **The DNS server**: zones of kinds `Primary`, `Secondary`, `Stub`, `Forward`, `Rpz` (`crates/tenko-core/src/dns.rs`); views select a scope per query by client subnet, transport, interface, type, name and time ([dns.md](../dns.md) section 11); ACLs (access control lists) gate transfers, updates and recursion, not authoritative answers; the `Resolver` trait (`crates/tenko-dns/src/resolver.rs`) is the one seam every transport calls, and the query path reads memory only. No DNS-SD names are generated anywhere. In Phase 2 and 3 the `dns` role runs in the controller's process and reads the store directly; the subsets a separate DNS node receives are declared for Phase 5 (`crates/tenko-cluster/src/node_sync/tables.rs`).
- **The DHCP server** sends option 15 (domain name), option 119 (domain search, RFC 3397) and DHCPv6 option 24 (domain list) from option sets at every level (server, shared network, scope, pool, reservation).
- **Observations** (`crates/tenko-ipam/src/observe/`, [reconciliation.md](../reconciliation.md) section 2): facts in `ipam.obs.facts` keyed by source and subject, purged after 30 days without a sighting; `Observed::Services` carries only an address and port lists. The host view is `/ipam/hosts/:fqdn` (`ui/src/hosts/HostView.tsx`), whose observation block is `ui/src/discovery/HostObservations.tsx`.
- **Profiles**: Home, Standard, Hardened, Lab; toggles end at TGL-39; TGL-18 (active probing) is passive only under Hardened unless enabled per segment; TGL-24 is the step-up ladder.
- **Labs** (`deploy/compose/`): `lab-dhcp` has four bridge networks and a router container joined to all of them, images built from `debian:12-slim` and `debian:13-slim`; no lab runs mDNS between two segments.
- **The store's data format** is 6; the public DNS plan's namespace may take 7 first (R175).

## 2. Design decisions the packages share

### 2.1 Links, pairs and rules

A **link** is a probe node and one of its interfaces, bound to one or more IPAM prefixes of role `network` in one VRF (`sd.links`, proposed): id, node, interface name, prefixes, a label (LDH: letters, digits and hyphens, for example `iot`) and a display name (rich text, for example `IoT devices`; by default the label), both used in the Discovery Proxy's names, the proxy's parent domain and the link's browsing domains where the DHCP scopes do not give them (section 2.10), learn mode on or off, and which of the two parts are enabled on it. A prefix belongs to at most one link. The binding is explicit, made by a person: a probe's scan scope is not enough, because a scan scope may list prefixes behind a router that the probe cannot hear by multicast.

An **ordered pair** (from, to) of links is the direction of a rule: announcements made on *from* are carried to *to*, and questions asked on *to* are carried to *from*. The reverse direction needs its own rule.

A **rule** (`sd.rules`) holds: the service type (`_ipp._tcp`, `_googlecast._tcp`), which of the type's subtypes it carries (proposed default: every subtype the selected devices announce for the type, such as `_universal._sub._ipp._tcp`, which some printing clients browse instead of the type; a subtype PTR points at the same instances, RFC 6763 section 7.1), the pair, the part (gateway, Discovery Proxy, or both), the devices (section 2.11, SD-Q3), whether announcements for other on-link addresses may cross (section 2.3, off), and the per-rule bounds within the global ones of section 2.8. The special type `_services._dns-sd._udp` (the list of types, RFC 6763 section 9) is never a rule: the gateway answers it on the destination link with the types it carries there.

### 2.2 The path of what crosses (SD-Q1)

```
 link iot                      controller                       link lan
 device --mDNS--> probe P1 ==(1) heard records==> policy ==(3)==> probe P2 --mDNS--> phone
                  listen,       mTLS stream      check, table     announce,
                  attribute,                     (2) sd.services  answer,
                  filter                          in the store    probe names
          <--mDNS-- query <==(4) question======= policy <==(4)=== question <--mDNS--
```

1. **Heard.** P1 listens on its link, decodes, attributes each announcement to a device (section 2.3), and keeps it in its link cache. Of what it hears it reports upward only what a rule names (or everything as a summary while learn mode is on), as **normalized records**: instance, type, SRV data, TXT strings, the addresses that pass section 2.6, the attribution and the remaining TTL. A packet never leaves the probe.
2. **Checked and stored.** The controller decodes strictly, checks each record against the rules again (the probe's filter is a saving, not the boundary), and writes the changes to `sd.services` in the store: one row per instance per link, written when it changes, not when it is refreshed (section 2.8).
3. **Handed over.** Every controller watches `sd.services` and streams to each connected destination probe the rows its rules allow on its links. P2 validates again, probes the unique names on `lan`, then announces and answers for them.
4. **Questions.** A question on `lan` for a carried type that P2 cannot answer fresh from what it holds becomes an interest message upward; the controller checks the rule and passes it to P1, which asks on `iot` with its own query (section 2.5).

A new stream `ServiceDiscovery.Exchange` on the node's existing mTLS connection carries steps 1, 3 and 4 (section 3.2). **Every event is bound to its sender:** the controller takes the node from the connection's certificate, never from the message, and refuses (and counts, with a finding) any event that names a link that is not one of that node's links, so a probe can speak only for its own links: heard records only for its links as source, interests and conflicts only for its links as destination. The store as the medium makes the design cluster-aware by construction: P1 and P2 may be connected to different controllers, and no controller-to-controller path is added. In a single-node installation the store is local and the hop costs a local commit.

**A probe with two links** (SD-Q6) runs the same path: its own records go through the controller like anyone else's, so the policy and the audit have one place.

### 2.3 Listening and attribution on the source link (SD-Q4)

**Sockets.** One UDP socket per link and address family, bound to port 5353 with `SO_REUSEADDR` and `SO_REUSEPORT`, bound to the interface with `SO_BINDTODEVICE` (as the DHCP server does), joined to `224.0.0.251` and `ff02::fb` on that interface's index, with `IP_MULTICAST_IF` and `IPV6_MULTICAST_IF` set to it, the multicast TTL and hop limit 255, the unicast TTL and hop limit (`IP_TTL`, `IPV6_UNICAST_HOPS`) 255 as well (RFC 6762 section 11 asks for 255 on every response, unicast ones included), and multicast loopback off. `SO_BINDTODEVICE` needs `CAP_NET_RAW` on Linux before 5.7, which `probe.conf` grants; from 5.7 an unbound socket may bind to a device without it **(unconfirmed; WP17.1 checks on the lab's kernel and records it)**. The scanner's passive listener reads from the same sockets when its link exists, so the probe holds one socket per link and family, not two that compete for port 5353 (WP17.1 moves it).

**Checks on every packet, in order:**

1. Size at most 9,000 bytes (RFC 6762 section 17), then a full decode within the bounds of section 2.8; a packet that fails is counted and dropped.
2. Source port 5353 for responses that will be carried (RFC 6762 section 6: responses are sent from 5353); a query from another port is a legacy one-shot query and is answered by unicast only (section 2.4).
3. The source address is on the link: inside one of the link's prefixes, or link-local (`169.254.0.0/16`, `fe80::/10`) on this interface. This is Tenko's own rule, stricter than RFC 6762 section 11, which treats every packet sent to the multicast group as local whatever its source and applies the on-link check to unicast packets only; a probe that carries records to another link cannot take a packet's word for where it came from. A packet from any other address is dropped; this alone stops a firewall's repeater, which sends from its own address on the link, from being heard as a device unless its address is in the link's prefixes (section 2.7).
4. The source is not a Tenko probe: the controller tells each probe the addresses that other probes hold inside that probe's own links (nothing about other links), and packets from them are dropped.
5. **Attribution.** The device is the source address, with its MAC address (media access control address, the hardware address) read from the kernel's neighbor table through netlink (which `probe.conf` allows; the scanner already reads it) and, when IPAM knows the MAC or the address, the IPAM host. A record is carried only when the A and AAAA records of the SRV target are inside the link's prefixes and include the packet's source address, or an address that the neighbor table maps to the same MAC as the source: a device announces itself. The MAC match matters for IPv6, where mDNS is usually sent from the device's `fe80::` address while its announcement lists only its global or unique local addresses. Announcements for other on-link addresses, such as a sleep proxy or a hub that announces for the devices behind it (a Thread border router announces Matter devices whose addresses are on the mesh behind it), cross only when the rule allows it, and then only for addresses inside the link's prefixes or in prefixes the rule names.

**What attribution cannot do.** A host on the same link can forge another host's source address and MAC; nothing a UDP socket sees tells them apart. This is the power any device on a link already has over its neighbors (it could take the address itself by ARP); the bound is that it reaches only the services the rules name, and every carried record names the device it was attributed to (audit, host view).

### 2.4 Announcing and answering on the destination link: the rules a proxy follows (SD-Q2)

The destination probe is the responder for what it carries: it speaks from its own address, with the original names, and follows RFC 6762 as any responder does, with three deliberate restrictions (it never defends, never renames, and never answers unicast from off its link).

| RFC 6762 rule | What the gateway does |
|---|---|
| Responses from UDP port 5353 with IP TTL 255 (sections 6 and 11) | Every packet it sends, from the probe's address on the link |
| A record multicast at most once per second per interface, 250 ms for probe defense (section 6) | Enforced per record and link; the gateway never defends, so the 250 ms case never occurs |
| Answers to shared records (PTR) after a random 20 to 120 ms, 400 to 500 ms when the query has the TC bit; unique records verified as unique may be answered at once (section 6) | The same delays; unique records answered within 10 ms |
| Known-answer suppression: a record the query lists with at least half its true TTL is not sent (section 7.1); lists continued over several packets with TC (section 7.2) | Honored, with the 400 to 500 ms wait for a continued list |
| Duplicate answer suppression: a responder that sees another host answer the same record with at least its TTL does not repeat it (section 7.4) | Honored; this is what keeps a firewall's repeater and the gateway from doubling every answer while both run |
| Unicast-response (QU) questions (sections 5.4 and 18.12) | Answered by unicast to an on-link querier, by multicast when the record was not multicast on the link within a quarter of its TTL |
| Legacy one-shot queries from a port other than 5353 (section 6.7) | Answered by unicast to the querier's address and port, with the query's ID and question, without the cache-flush bit, TTL at most 10 s; only from an on-link source |
| Direct unicast queries to the probe's address (section 5.5) | Answered only from an on-link source, silently dropped otherwise |
| Probing: before first use of a unique name, three probes 250 ms apart after a random 0 to 250 ms delay, with the proposed records in the Authority section (section 8.1) | Done for each unique name it will announce (the SRV and TXT owner, which is the instance name, and the host name of the SRV target), on the destination link |
| Tiebreaking and conflict: the loser renames itself (sections 8.2 and 9) | **Never renamed, never defended.** A conflict during probing, or a later announcement of the same unique name with other data by a host of the link, makes the gateway withdraw that name's records (goodbye) and raise `sd.conflict` naming both devices. It does not answer probes of others for a carried name, so a host of the link that probes the name finds it free and takes it. The host of the link always wins. The gateway probes the name again only after the local host's records have expired or been withdrawn, and at most once an hour. Section 9 says a responder that loses MUST choose a new name and probe again; withdrawing instead is a deliberate deviation, recorded in CONFORMANCE |
| Announcing: at least two unsolicited responses one second apart, up to eight with the interval at least doubling (section 8.3) | Two announcements after probing; then only answers to questions, no periodic announcements |
| The cache-flush bit on unique records, never on shared records, known-answer lists or legacy unicast answers (section 10.2) | Set on carried SRV, TXT, A, AAAA and NSEC after probing; never on PTR |
| Goodbye: the record with TTL 0, which receivers treat as TTL 1 (section 10.1) | Sent when the source device sends its goodbye, when a rule or a device is removed from a rule, when a toggle of section 3.4 is turned off, when the record leaves the bounds, and when the probe stops |
| Negative answers by NSEC for the types a unique name lacks (section 6.1) | Synthesized for each carried host name and instance name, listing the types it carries (block 0 only, as section 6.1 asks) |
| TTLs: 120 s for records whose name is a host name (A, AAAA) or whose data contains one (SRV), 75 minutes (4,500 s) for others, here PTR and TXT (section 10); a querier refreshes at 80 percent of the TTL | Carried with the TTL that remains of the original, never longer, never above those two values |

Why the restrictions: a proxy that defended a carried name would let a device on the source link take names on the destination link, which is the conflict attack section 2.14 names; a proxy that renamed would change identities that some protocols keep in the instance name (SD-Q2).

**Names the destination link already uses.** "The host of the link always wins" holds only while that host is awake: a printer that sleeps does not answer probing. So the controller refuses to carry an instance name or host name that the destination link has used within 30 days (the observation facts of its prefixes, which keep 30 days, and the destination probe's link cache), and raises `sd.conflict` instead. Names with bidirectional-text or invisible format characters (Unicode categories Cf and the bidirectional controls) are never carried. A name that differs from one used on the destination link only by letter case, width or white space is refused under Hardened and carried with the finding `sd.lookalike` elsewhere; a fuller check of confusable characters (Unicode's UTS #39 skeletons) needs a data table, and WP17.2 weighs a crate against our own small table before proposing either (R188).

### 2.5 Questions that cross

A question on the destination link for a carried type is answered at once from what the gateway holds when that is fresh (more than half the TTL left). Otherwise the gateway sends an **interest** upward: (destination link, name, type), at most one per name and type per second, and one already pending is not repeated. The controller checks that a rule allows it and passes it to the source probe, which asks on its link with its own query: from port 5353, as a fully compliant querier, with the records it already holds as known answers, at most 20 query packets per second per link (the rate RFC 8766 section 9.3 recommends for a Discovery Proxy on a wireless link). It skips its query when another host asked the same question on the link within the last second and that query's known-answer list holds every record the probe would itself have listed (duplicate question suppression, RFC 6762 section 7.3); a query whose list lacks one of them does not count. The answers come back as heard records along the normal path of section 2.2. The client's packet never crosses, and nothing on the source link learns who asked.

While a rule exists, the source probe also refreshes the records it carries at 80 percent of their TTL with a query of its own, aggregated into one packet per link per second, so that what the destination holds stays fresh without a question.

### 2.6 What crosses: record types, names and addresses

| Record | Crosses | Name and data on the destination link |
|---|---|---|
| PTR `_type._tcp.local` (and a subtype's PTR) | Yes, for the rule's type | Unchanged; shared, no probing, no cache-flush bit |
| SRV `<instance>._type._tcp.local` | Yes | Unchanged instance name and target host name; probed |
| TXT of the instance | Yes, up to 1,300 bytes (section 2.8) | Unchanged; probed with the SRV |
| A of the SRV target | Yes, addresses inside the link's prefixes only | Unchanged; `169.254.0.0/16` never crosses (it is valid only on its own link) |
| AAAA of the SRV target | Yes, global and unique local (`fc00::/7`) addresses inside the link's prefixes | Unchanged; `fe80::/10` never crosses |
| NSEC | Never carried from the source | Synthesized by the gateway for the names it carries (section 2.4) |
| Any other type (HINFO, `_device-info._tcp` records, unknown types) | No | Answered with the synthesized NSEC |
| `_services._dns-sd._udp.local` | Not carried | Answered by the gateway with the types it carries on that link |

**IPv4 and IPv6.** Both groups are joined on both links. An IPv4-only and an IPv6-only host on one link see separate `.local` spaces (RFC 6762 section 20); the gateway answers in each family with the records of both, and puts the other family's addresses in the Additional section, as section 6.2 asks of every responder. A device that has only link-local addresses of one family is announced with the other family only; a device with no address that may cross is not carried, and the learn view says why (`sd.no_routable_address`).

**Names are not rewritten** on the gateway (SD-Q2). The `.local` names keep their meaning: a name the device holds on its link, now also answered for on the destination link by the gateway, which yields at the first sign of a local owner.

### 2.7 Loops and other repeaters

No record can travel back to its origin, for four independent reasons:

1. Every row of `sd.services` names its origin link; the controller never hands a row to a probe for its origin link, and a destination probe never reports a record it carries as heard.
2. A probe drops packets whose source is a Tenko probe (section 2.3, check 4), so the records one gateway announces are not heard as devices by another.
3. Records heard from a source outside the link's prefixes are dropped (check 3), and the attribution rule needs the record's addresses to include the source address (check 5). A firewall's repeater on the link sends copies of the other link's records from its own address; their addresses are not on this link, so they are not originated here.
4. Bounds (section 2.8) hold whatever happens, so a loop that the first three miss cannot grow.

**A firewall's repeater on the same pair.** Run together, the repeater copies the device's packets to the destination link and the gateway announces the same records there: same names, same data, so no conflict (identical data is not a conflict, RFC 6762 section 9), and duplicate answer suppression halves the doubled answers. The gateway detects a repeater when it hears, on a destination link, records it carries arriving from a source that is neither the device nor a probe, and raises `sd.repeater_detected` with the source address. The operator's page says to turn the firewall's repeater off for the pairs Tenko serves. Tenko never talks to the repeater.

### 2.8 Bounds

mDNS is unauthenticated: every number below bounds what one device, one link or one pair can cost. Each is a global maximum; a rule may lower it.

| Bound | Value (proposed) | Reason |
|---|---|---|
| Packet read | 9,000 bytes | The largest mDNS message (RFC 6762 section 17); the scanner's bound today |
| Records per packet, questions per packet | 256, 32 | The scanner's bounds today, measured against the fixtures |
| Name, instance label | 255 octets, 63 octets | RFC 1035 and RFC 6763 section 4.1.1 |
| TXT data carried | 1,300 bytes per instance | RFC 6763 section 6.2: larger TXT records do not fit one Ethernet packet with the other records; printer TXT records of 500 to 1,000 bytes fit (RFC 8766 section 5.5.5). Larger: not carried, `sd.oversized` |
| Packets heard per source | 20 per second averaged over 10 s, bursts of 40; an IPv6 source counted by its `/64`, as the DNS server's update admission groups clients | A responder multicasts a record at most once per second (RFC 6762 section 6); a device with many services at start-up sends a few packets per second; above the bound the source is muted for 60 s and `sd.flood` is raised. Counting by `/64` stops a flood from spoofed addresses of one prefix from escaping the bound |
| Rate limiter state | 1,024 sources per link; when full, the least recently heard source not selected by a rule is dropped | Bounds memory under a flood of spoofed sources |
| Packets heard per link | 400 per second; above it, packets from sources no rule selects are dropped first | Twice the saturation rate of a wireless link (RFC 8766 section 9.3); the probe's work stays bounded whatever the number of sources |
| Instances carried per device | 16 per type, 32 in all | A multi-function printer announces under five to ten types; margin for the rest |
| Address records per host | 8 | A host with stable, temporary and unique local IPv6 addresses and one IPv4 address has five or six |
| Instances carried to one link | 512 | A home has tens, a small office one to two hundred |
| Link cache (everything heard, for learn mode and the proxy) | 4,096 records per link; at most 64 records per device; records of devices a rule selects are never evicted by others; among the rest the least recently heard goes first | The scanner's per-run bound of 4,096 addresses; fits M77; a flood cannot push out the devices that cross |
| Packets sent by the gateway per link | 50 per second and 64 KiB per second; each packet at most the interface's MTU (maximum transmission unit) less the headers and, where the records allow, at most 1,500 bytes | A quarter of the 200 packets per second that RFC 8766 section 9.3 names as enough to saturate a wireless link; RFC 6762 section 17 on packet sizes |
| Query packets sent per source link | 20 per second | RFC 8766 section 9.3 |
| Interests per destination link | 1 per name and type per second, 10 per second in all | Bounds the amplification of questions through the gateway |
| Exchange stream per probe | 200 changes per second and 256 KiB per second upward | Ten times the expected steady load of a full link; a probe above it is throttled and `sd.exchange_throttled` raised |
| Store writes of `sd.services` | Changes only, at most 50 per second per link; the row's `valid_until` rewritten at most every 15 minutes | TTL refreshes are not changes; 15 minutes is the observations' refresh interval |
| Carried TTL | The remaining TTL, at most 120 s for A, AAAA and SRV and 4,500 s for PTR and TXT | RFC 6762 section 10 |
| Discovery Proxy interests | Only for names under a subdomain and of a type a rule names; 1 per name and type per 10 s, 10 per second per subdomain; a queue of 256 that never makes a query wait and drops new interests when it is full or no controller is reachable | A client allowed to ask could otherwise make the source probe query the untrusted link at the client's pace |
| Learn mode | 1,024 rows per link, ends after 24 hours | Long enough to see devices that announce rarely; bounded for privacy (section 2.12) |
| Discovery Proxy answers | TTL 10 s; at most 512 instances in a browse answer (UDP truncates to the EDNS size and the client retries over TCP) | RFC 8766 section 5.5.1; the per-link bound above |

### 2.9 When the controller is unreachable, and restarts (SD-Q5)

CONTRIBUTING rule 5 keeps the data plane independent of the control plane. The gateway's data comes through the controller by design (SD-Q1), so the question is what the destination probe does with what it already holds:

- **Policy is kept.** The probe's part of the configuration (its links, the types to listen for and report, learn mode) arrives through `Config.Watch` and is kept in `state.cbor`, as every node configuration is.
- **Carried records are kept in memory only**, and served until their own TTL runs out; nothing new crosses; no goodbye is sent, because the device may well still exist and a goodbye would remove it from every client cache at once. The exposure after a revocation the probe did not hear is bounded by the TTL: 120 s for the addresses and the SRV record (without which a client cannot connect), 75 minutes for the PTR and TXT records (with which a client still lists the service).
- **After the connection returns** the controller streams the current set; the probe announces what is new, sends goodbyes for what is gone, and is complete within 10 s (E107).
- **A probe that restarts** starts with nothing carried and waits for the controller. **A probe that stops** sends goodbyes for everything it carries (RFC 6762 section 10.1).
- **The Discovery Proxy** answers from `sd.services` rows whose `valid_until` has not passed. Today the DNS server runs in the controller's process, so "the controller down" means the probes cannot reach it while it runs, or that it is stopped and nothing answers at all; in Phase 5, with separate DNS nodes, it means the DNS node keeps its copy of the table. In both cases the rows stop being refreshed, and 30 minutes (two refresh intervals) later the subdomains answer with no records.

### 2.10 The Discovery Proxy (part b; SD-Q7 to SD-Q10)

RFC 8766 describes a server that is authoritative for a subdomain per link and answers unicast DNS queries there by asking on the link by mDNS. Here the asking is done by the probe of the link, and the answering by Tenko's DNS server from the service table.

**Names (SD-Q9).** A source link with the part enabled has a *parent* domain, set on the link: by default `sd.` under the first domain of the DHCP option 119 list (else option 15) that Tenko's DHCP scope for the link's first prefix sends, which must be a zone Tenko serves (for `example.test`: `sd.example.test`); when Tenko is not the link's DHCP server or no such domain is set, the operator names the parent and the part cannot be enabled without one. Under the parent the link has two subdomains, as RFC 8766 section 5.3 asks (a proxy SHOULD offer an LDH subdomain for host names and MUST NOT offer only that one): the **rich-text subdomain** for the services, labeled with the link's display name, which may hold spaces and UTF-8 (`IoT devices.sd.example.test`; RFC 6763 section 4), and the **LDH subdomain** for host names, labeled with the link's LDH label (`iot.sd.example.test`). When the display name is itself an LDH label, the two are one subdomain. Instance names keep their rich text; host names in SRV targets are rewritten from `printer.local` to `printer.iot.sd.example.test`. Only the suffix changes: the label before `.local` stays, and nothing is translated between Punycode and UTF-8 (RFC 8766 section 5.5.4). These names live beside the internal zone's own names: a device that IPAM also knows as `printer.example.test` keeps that name, and the host view shows both.

**How clients find the subdomain.** RFC 6763 section 11 has a client ask for the PTR records `b._dns-sd._udp` (browsing domains), `db._dns-sd._udp` (the default one) and `lb._dns-sd._udp` (legacy browsing, used without asking the user) under each domain of its search list, and under the reverse name of its own network (its address masked with its prefix length, for example `lb._dns-sd._udp.0.2.0.192.in-addr.arpa` for `192.0.2.0/26`, not for link-local addresses). Tenko answers those names in every zone it serves that is in the search list the DHCP scope of the destination link sends (option 119, else option 15; DHCPv6 option 24), and in the reverse zone of each destination prefix, with a PTR to each source link's rich-text subdomain that a rule makes visible from that link. When Tenko is not the destination link's DHCP server, the operator lists the link's browsing domains on the link. The operator sets the search domain in DHCP as today; nothing new is sent to clients. The names are generated answers, not stored RRsets, and are visible only to the clients of section "Who may ask" below.

**Answers (SD-Q7).** A synthesized zone per subdomain (proposed `ZoneKind::Discovery`), built by the DNS server from the `sd.services` rows of its link into an immutable snapshot whenever they change, and swapped in as the other zones' snapshots are, so the query path stays memory-only. Answers:

- PTR, SRV, TXT, A and AAAA of the carried instances, with TTL 10 s and a negative TTL of 10 s (RFC 8766 section 5.5.1);
- the SOA with serial 0, refresh 7,200, retry 3,600, expire 86,400 and minimum 10 (section 6.1), and NS records naming the DNS server's own name;
- no link-local, private or unique local address when the client is outside the realm of the link (section 5.5.2): here every client allowed to ask is inside the site, so private and unique local addresses of the site's prefixes are answered and link-local ones never are; an SRV whose target has no address left is dropped, and so is the PTR that points at it;
- answered at once as absent: SOA, NS and DS queries for names below the subdomain's apex (section 6.3), and `_dns-update._udp`, `_dns-update._tcp`, `_dns-update-tls._tcp`, `_dns-llq._udp`, `_dns-llq._tcp`, `_dns-llq-tls._tcp` and `_dns-push-tls._tcp` under the subdomain (section 6.4), so that clients neither try to register nor wait for Push or LLQ;
- **the delegation:** the parent zone's snapshot carries NS records for each subdomain (and no DS, an insecure delegation), in its answers and in its zone transfers, so that a secondary of the parent zone refers clients to the subdomain instead of answering NXDOMAIN, and a signed parent zone proves that the subdomain is unsigned (RFC 8766 sections 5.1 and 6.2).

**Timing.** RFC 8766 section 5.6 has the proxy answer a cached name at once and, on a miss, ask on the link and wait up to 6 seconds for a first answer before it returns an empty answer. The DNS server cannot wait without a deferred-answer path, and the proxy's data lives on another node. So (proposed) a miss answers at once with no records and the negative TTL of 10 s, and records an interest that makes the source probe ask on its link; the client's next query, at most 10 s later, finds the answer. The query path records an interest without waiting and without a lock: it offers it to a bounded queue that drops it when full, and a task outside the query path takes it to the controller (bounds in section 2.8; with no controller reachable the interests are dropped, CONTRIBUTING rule 5). Only names under the subdomain of a type a rule names produce an interest. To make misses rare, a link with the part enabled keeps the listed types fresh: its probe browses them at 80 percent of their TTL whether or not someone asked. CONFORMANCE records the deviation.

**Who may ask (SD-Q10).** A query for a subdomain, or for a browsing name that lists it, is answered only when the client's address lies in a prefix of a destination link of a rule whose source is that subdomain's link and whose part includes the Discovery Proxy; otherwise REFUSED. The check is an ACL the DNS server derives from the rules, intersected with an optional ACL the operator sets per subdomain. Today authoritative answers have no ACL in Tenko; this is the first, and it lives with the synthesized zone, not in the general path. The ACL sees the address that sent the query, which is the client only when the client asks Tenko directly. A forwarder between them (the firewall's own DNS service, for example) either serves only one destination segment, and is then listed in the operator's ACL by its address, or serves several segments, and then the proxy cannot tell their clients apart: Tenko raises `sd.proxy_forwarder` when queries for a subdomain arrive from an address outside every destination prefix, and the operator's page says that the destination segments' clients must use Tenko as their DNS server (as Tenko's DHCP scopes hand out) for the proxy to work.

**DNSSEC.** The subdomains are not signed (section 1.4); the parent delegates them insecurely (above).

### 2.11 Policy, learn mode, roles and audit (SD-Q3, SD-Q13)

**Defaults.** Off in every profile: no link exists after installation, and a link without rules carries nothing. The two parts are separate toggles (section 3.4).

**Learn mode** is turned on per link by a person and ends by itself after 24 hours. The probe listens continuously and reports a summary per (device, type): instance names, port, first and last heard, the size of the TXT data, whether its addresses would pass section 2.6. The UI lists them with the rule each would need, and "Allow" creates that rule with the device filled in; nothing crosses before the rule is saved. Learn mode keeps its rows in the memory of the controller the probe is connected to (section 2.12); on a single node that is all there is, and in a cluster the API gathers the rows from each controller over the cluster's internal API (built with the Phase 5 cluster data plane, not here).

**The gateway's own traffic and TGL-18.** The gateway sends mDNS queries on the source link and answers on the destination link. That is the service the operator turned on per pair, governed by the two toggles of section 3.4, not scanning: TGL-18 (active probing) does not apply to it, and under Hardened the administrator's enabling of a pair is the explicit consent. The flow test of section 2.13 is scanning and does follow TGL-18.

**Devices in a rule (SD-Q3).** A rule names its devices: an IPAM host, a MAC address or an address of the source link. Under Home and Standard a rule may instead say "any device of the source link"; then a device crossing for the first time raises the finding `sd.new_device` (info) with the device and the rule, so that a person sees it. Under Hardened a rule must name its devices.

**Permissions** (proposed): `sd.read` to see links, rules, learn results and services; `sd.write` to change links, rules and learn mode under Home and Standard (in the network operator's role); under Hardened only an administrator, with the TGL-24 step-up (a passkey or hardware key within five minutes), per ordered pair.

**Audit actions**: `sd.link.create`, `sd.link.update`, `sd.link.delete`, `sd.rule.create`, `sd.rule.update`, `sd.rule.delete`, `sd.learn.start`, `sd.learn.stop`, `sd.flow.test`. Each change names the pair, the types and the devices. The crossing itself is not audited per record (it is a data plane); it is counted in metrics and listed in the services view.

### 2.12 The host view and privacy (SD-Q11)

A service instance name is often a person's name ("Alex's phone", "Office of J. Doe"), and some TXT values carry user names, device serial numbers or account identifiers. RFC 8882 section 3.2.2 names instance names as a leak of a person's presence. What Tenko keeps:

| Data | Kept | Where and how long |
|---|---|---|
| Service type, port, the instance name, the SRV target's host name, the links it crosses to | Yes, for instances a rule names | A new fact kind `Observed::Service` in `ipam.obs.facts`, source `probe:<node>:mdns`, purged with the other facts after 30 days without a sighting (`ObserveConfig::retention`) |
| The same for instances heard but named by no rule | Only while learn mode runs | The controller's memory; gone when learn mode ends or the controller restarts |
| TXT data | The key names and the total size only, never a value | The fact above; the gateway and the proxy hold the values in memory to serve them |
| `sd.services` rows (what the proxy and the gateway serve) | Values included, as served | Deleted when the record's goodbye arrives or `valid_until` passes |
| Logs | No instance name or TXT value in a log line; counts and device addresses only | As the logs |

Under Hardened (proposed) the host view shows the instance name only to `sd.read` holders, the facts follow the shortest retention the site has configured for personal data (OPS-06), and learn mode is limited to administrators. What crosses is the operator's choice by rule: the gateway never carries the services phones and computers announce about themselves unless a rule names them.

**The host view** gains a block "Services": type, instance, port, the links it is heard on and carried to (with the rule), the last time heard, and findings about it (`sd.conflict`, `sd.flood`, `sd.flow_blocked`). The services page under Discovery (`/discovery/services`, proposed) lists the same across all devices, by link and by rule.

### 2.13 The firewall: what must still be allowed, and what Tenko tells (SD-Q12)

Discovery only tells a client where a service is; the client then connects by unicast to the device's address on the other segment, through the router and its firewall. A service that is discovered but blocked is worse than one that is not found: the user sees it and it fails. The firewall must allow, from the destination prefix to the device's address:

- the port of the SRV record, with its protocol (`_tcp` or `_udp` in the type): Tenko knows it for every carried instance;
- the further flows a protocol needs beyond the SRV port, for example media streams from the sender to the receiver, or a receiver's connections back to the sender: these are per protocol and per vendor and are not in DNS-SD; a catalog per service type (`crates/tenko-scan/data/sd-flows.toml`, proposed), filled by WP17.2 from the vendors' public documentation with the date read, lists them **(unconfirmed: the contents of each entry; IPP on TCP 631 is the IANA assignment and the one entry stated here)**;
- the return traffic, which a stateful firewall allows by itself.

The gateway itself needs no firewall rule between the segments: both probes talk only to the controller, as every probe already does.

**What Tenko does.** Per rule, the flows view lists each carried device with its flows as text an operator can copy into the firewall ("from `192.0.2.0/26` to `192.0.2.70` TCP 631"). A **reachability test** from the destination probe (a TCP connection attempt to the SRV port from the destination link, which is the path a client takes) reports *reachable*, *refused* (routed, nothing listening) or *no answer* (probably filtered), and raises `sd.flow_blocked` for the last. The test is active probing: it follows TGL-18 (passive only under Hardened unless enabled per segment), is started by a person or after a rule change, at most once per device and port per hour, and is audited (`sd.flow.test`). UDP services are listed but not tested (a UDP test proves nothing without the protocol).

**What Tenko never does.** It never changes a firewall: no call to a firewall's API, no rule written through a connector (the network controller connector reads topology and never writes), no UPnP (Universal Plug and Play), NAT-PMP or PCP (Port Control Protocol) request that opens a port, no advice to disable the firewall or the segmentation. A firewall is a security boundary the operator owns; a program that crosses it on its own would make Tenko the way around it.

### 2.14 Security, in the owner's order

| Threat | Bound |
|---|---|
| A device on the source link announces a service that redirects clients to another host (a fake printer pointing at a collecting server elsewhere) | Attribution (section 2.3): the record's addresses must be on its link and include its own source address; the rule names the type and, under Hardened, the device; the host view and the services view name the device each record came from |
| A device impersonates a known device on the destination link (same instance or host name), also while that device sleeps, or with a lookalike name | The host of the link always wins (section 2.4); names the destination link used within 30 days are not carried; format and bidirectional characters never; case and width lookalikes refused under Hardened, flagged elsewhere (section 2.4); the gateway never defends or renames; `sd.conflict` names both |
| A probe speaks for a link that is not its own | Every exchange event is bound to the node of the connection's certificate (section 2.2) |
| A device provokes conflicts so that devices on the destination link rename themselves | The gateway never answers a probe for a carried name and yields to the first announcement of a local host, so no local host ever loses a probing contest to a carried record (E104) |
| Amplification: a small question makes the gateway send many large answers, or makes the source probe query on its link | Answers follow known-answer suppression and the once-per-second rule; the gateway's send rate per link, interests per link and queries per source link are bounded (section 2.8); unicast answers go only to on-link sources; the proxy's subdomains answer only allowed clients, use the DNS server's rate limiter and the TCP fallback for large answers, and raise interests only for the rules' types, within their own bound |
| Floods of announcements, instances or large TXT records, also from many spoofed sources | Per-source rate with muting (an IPv6 source counted by its `/64`), a bounded limiter table, a per-link packet bound, per-device and per-link instance counts, a per-device share of the link cache that protects the devices rules select, the TXT bound (section 2.8, E106) |
| Loops between two gateways, or with a firewall's repeater | Section 2.7 (E105) |
| A crafted packet that exploits the parser | A memory-safe codec on `domain` with bounds before allocation; the fuzz target `mdns_message` (E100); the controller and the destination probe re-validate normalized records strictly (fuzz target `sd_exchange`) |
| A compromised probe on the untrusted segment | It is the source of its link's records, so it can make up any record for its link within the rules: types, devices (it reports the attribution) and bounds. It cannot reach another link except through the controller, which re-checks every record against the rules and the bounds, and the destination probe re-validates. The plan says plainly that the rules, not attribution, are the boundary against a lying probe. ADR 0023 holds: the probe gains no privilege, and nothing it sends is executed or parsed as code by a more privileged account |
| The destination probe as a foothold: a device on the untrusted link reaches a process with a leg on the trusted link | Only on a probe with two links (SD-Q6), which Hardened refuses for the two links of one pair; the probes of separate links share no process |
| Privacy: names of people and their devices crossing or kept | Section 2.12 |
| The proxy reveals the untrusted segment's devices to anyone who can query the DNS server | The derived ACL (section 2.10) |

**The Hardened profile** (SD-Q13, proposed): both parts off until an administrator turns them on per ordered pair with the passkey step-up; rules name their devices; announcements for other addresses refused; learn mode administrators only; the reachability test only where TGL-18 is enabled for the segment; the Discovery Proxy's ACL as derived, without "any"; a probe with both links of a pair refused; instance names shown to `sd.read` holders only and kept with the site's shortest personal-data retention.

### 2.15 Performance budget

The probe is a small node, often a VM with one virtual CPU and 512 MiB of memory (proposed as the reference for M77 and M78, measured on the release binary as every measurement is). The budget, per probe with two links at every bound of section 2.8 filled:

- **Memory:** at most 32 MiB of resident growth over the idle probe; for a typical home link (100 instances, 300 records) at most 4 MiB. The link cache dominates: 4,096 records of at most about 1.6 KiB each (name, TXT bound, bookkeeping) is under 7 MiB per link.
- **CPU:** at most 5 percent of one core at 200 packets per second heard per link (the saturation rate of a wireless link) for 10 minutes, and a p99 under 1 ms from a packet's arrival to its decision.
- **Latency:** from an announcement on the source link to the first announcement on the destination link, at most 1.5 s for a new name (probing takes 0.75 s plus the delays) and 300 ms for a change of a carried record; a question answered from what the gateway holds within the RFC's delays.
- **The DNS server:** building a subdomain's snapshot from 512 instances in under 50 ms; the query path unchanged (the existing no-allocation test covers the new zone kind).

Measured by M77 to M80 (section 5.2), in the lab with the flood generator and on the release binary.

### 2.16 Dependencies, capabilities and ADR 0023

**The codec: no new crate.** `domain` 0.12.3, already the workspace's codec, parses and builds messages with any class value (the class is a 16-bit integer), has NSEC with its type bitmap, and builds messages with name compression. What is missing is Tenko's own code: a lossless mDNS message model over `domain` that keeps record data bytes, reads NSEC, joins known-answer lists across packets, encodes responses with the top bit of the class field per record and per question, and enforces the bounds. The scanner's parser moves onto it (WP17.1), so the workspace keeps one mDNS parser. Weighed against the owner's rule: the use share of `domain` grows (its builder and the NSEC type), the tree cost is nil (already in the tree), and writing a second codec ourselves would be a second parser for one job.

**Sockets: no new crate.** `socket2` 0.6.5 (in the tree, used by the scanner and the DHCP server) has per-interface multicast joins, `IP_MULTICAST_IF`, multicast TTL and loopback settings, and `bind_device`. No control-message parsing (`IP_PKTINFO`) is needed, because each socket is bound to its interface. `nix` and `libc` are in the lock file through other crates; this plan does not use them directly.

**Neighbor table:** read through netlink as the scanner already does.

**Capabilities.** The gateway needs what `probe.conf` grants today (`CAP_NET_RAW` for `SO_BINDTODEVICE` on kernels before 5.7) and no new address family; the base unit and the other roles are untouched. No new drop-in and no change of the hardening gates. `probe.conf` is optional today (the probe's passive methods work without it); on a kernel before 5.7 the gateway needs it, and a link cannot be enabled on a probe that reports it cannot bind to its interface (the probe says so in its configuration report, and the UI tells the operator to install the drop-in, which is a host change by root at the operator's hand, as ADR 0023 has it).

## 3. Contracts and shared files (WP17.0)

### 3.1 Types (`tenko-core`)

`crates/tenko-core/src/sd.rs` (new): `LinkId`, `Link { node, interface, prefixes, label: DnsLabel, learn: Option<LearnUntil>, parts }`, `RuleId`, `Rule { service_type: ServiceType, from: LinkId, to: LinkId, parts: Parts { gateway, proxy }, devices: DeviceSelector { Any, Listed(Vec<DeviceRef>) }, others_allowed: Option<Vec<Prefix>>, bounds: RuleBounds }`, `DeviceRef { Host(HostId), Mac(MacAddr), Address(IpAddr) }`, `ServiceType` (validated `_name._tcp` or `_name._udp`, optionally with a subtype), `CarriedInstance { origin: LinkId, instance: InstanceName, service_type, srv: SrvData, txt: TxtData, host: HostLabel, addresses, device: Attribution, ttl, valid_until }`, with validation and property tests. `crates/tenko-core/src/observe.rs` gains `Observed::Service { ip, service_type, instance, port, host, txt_keys, txt_len, carried_to }` (a shared file: the lead grants the additive change).

### 3.2 Protocol

`crates/tenko-cluster/proto/tenko/cluster/v1/discovery.proto` (new): service `ServiceDiscovery` with `Exchange(stream ProbeEvent) returns (stream GatewayDirective)`. `ProbeEvent` is one of `Heard` (link, normalized instance, attribution, remaining TTL), `Gone` (goodbye or expiry), `Interest` (destination link, name, type), `LearnSummary`, `Conflict`, `RepeaterSeen`, `FlowResult`. `GatewayDirective` is one of `Carry` (destination link, instance), `Withdraw`, `Ask` (source link, name, type), `ProbeAddresses` (the addresses other probes hold inside the receiving probe's own links, for section 2.3, and nothing else), `TestFlow`. The probe's links and learn settings travel in its node configuration through `Config.Watch`, validated by the same code as the API (and covered by the fuzz target `node_config_payloads`). Within the cluster protocol's current version, additive.

### 3.3 Store, API, CLI, codes

- The namespace `sd` with `sd.links`, `sd.rules`, `sd.services` (one row per carried or proxied instance per link, written on change) and `sd.flows` (the last test per device and port). `sd.services` joins the `dns` role's subset when DNS nodes leave the controller's process (Phase 5); today the DNS server reads the store directly. Whether the namespace needs data format 7 is WP17.0's first decision (R175).
- Routes under `/api/v1/service-discovery/`: `links` (CRUD and learn start and stop), `rules` (CRUD), `learn/{link}` (the summary), `services` (list, by link, by device), `flows` (list, test). Permissions as section 2.11.
- CLI: `tenko sd link|rule|learn|services|flows`.
- Codes `sd.*` (among them `sd.no_rule`, `sd.pair_same_link`, `sd.devices_required`, `sd.prefix_taken`, `sd.step_up_required`, `sd.label_invalid`); audit actions of section 2.11; findings `sd.flood`, `sd.conflict`, `sd.lookalike`, `sd.foreign_link` (an event for a link of another node), `sd.proxy_forwarder`, `sd.repeater_detected`, `sd.oversized`, `sd.unattributed`, `sd.no_routable_address`, `sd.new_device`, `sd.flow_blocked`, `sd.exchange_throttled`; metric families `tenko_sd_*` (packets heard and dropped by reason, records carried per link, interests, queries sent, packets sent, conflicts, mutes). Every audit action gets its English unit and Swedish target in `ui/i18n/<language>.d/labels.xlf` (the label catalog test).

### 3.4 Toggles

Two rows in [SECURITY-PROFILES.md](../SECURITY-PROFILES.md) (proposed TGL-42 and TGL-43: ADR 0032 proposes TGL-40 and the notifications plan TGL-41; the lead numbers them):

| Toggle | Home | Standard | Hardened | Lab |
|---|---|---|---|---|
| mDNS gateway between links | Off; `sd.write` may enable per pair | Off; as Home | Off unless an administrator enables it per ordered pair with the step-up; devices listed | Off; as Home |
| Discovery Proxy | Off; `sd.write` may enable per link | Off; as Home | Off unless an administrator enables it per link with the step-up; derived ACL only | Off; as Home |

### 3.5 Shared fixtures

`crates/tenko-scan/tests/fixtures/mdns/`: packets recorded in the lab (section 4, WP17.6) and converted to hex as the existing fixtures are: announcements of a printer, a casting-like receiver and a home-automation device (made with Avahi and python-zeroconf, synthetic names, documentation addresses), probes and conflicts, goodbyes, known-answer lists over two packets, QU and legacy queries, NSEC answers, and the hostile set (oversized, pointer loop, 300 records, a TXT of 2,000 bytes, off-link address records). Rows of `sd.services` for the DNS server's tests under `crates/tenko-dns/tests/fixtures/sd/`. No recording is ever made on the owner's network into the repository.

### 3.6 The ADR (proposed 0037)

It must decide:

1. What crosses is normalized records, never packets, through the controller and the store (SD-Q1), and nothing is bridged at layer 2.
2. The proxy's identity on the destination link: its own source address, the original names, probing before use, the local host always wins, never defend, never rename, and no name the destination link used within 30 days (SD-Q2); every exchange event bound to the sending node.
3. The attribution rule and its exception for announcements for others (SD-Q4).
4. The namespace `sd`, `sd.services` as the service table shared by both parts, its place in the role subsets, the data format.
5. The Discovery Proxy served by the DNS server from the table, cache-only with an interest on a miss, as a recorded deviation from RFC 8766 section 5.6 (SD-Q7), and the ACL derived from the rules (SD-Q10).
6. The behavior without the controller (SD-Q5).
7. Tenko never changes a firewall (SD-Q12).
8. The defaults, the toggles and the Hardened rules (SD-Q13), and the gateway as a Linux probe function within the grant of `probe.conf` (ADR 0023 unchanged).

## 4. Work packages

The packages own these trees, one package per file: `crates/tenko-core/src/sd.rs`, `crates/tenko-cluster/proto/tenko/cluster/v1/discovery.proto`, `crates/tenko-scan/src/mdns/**` (new), `crates/tenko-scan/src/sd/**` (new), `crates/tenko-dns/src/sd/**` (new), `crates/tenko-api/src/routes/sd/**`, `crates/tenko/src/cli/sd*`, `ui/src/discovery/services/**`, `deploy/compose/lab-mdns/**`, and the documents of section 10.

#### WP17.0 The contracts and the ADR (3 builder-days)

- **Requirements:** DNS-35.
- **Owns:** section 3 in code: the types with property tests, the protocol file and its conversions, the `Observed::Service` variant (with the lead), the namespace and its tables, the route stubs answering 501, the CLI stubs, codes, audit actions with their labels, findings, metric families, the two toggle rows, the UI route stub; the data format decision; the ADR as Proposed; `scripts/requirement-trace.mjs` widened to three-digit exit criteria with this plan in the Phase 4 list (with the lead).
- **Depends on:** the owner's decisions SD-Q1 to SD-Q6 and SD-Q9 to SD-Q13 (the contracts encode them); SD-Q7, SD-Q8 and SD-Q14 can follow.
- **Acceptance:** the workspace builds; the protocol round-trips; the label catalog test passes; the trace regenerated and `--check` passes for phases 1 to 4.

#### WP17.1 The mDNS codec, the link listener and the probe's source side (8 builder-days)

- **Requirements:** DNS-35, SCAN-01, SCAN-02, SCAN-04.
- **Owns:** `crates/tenko-scan/src/mdns/**` (the message model and codec on `domain`, the bounds, the per-link sockets for both families, the packet checks of section 2.3, attribution through the neighbor table, the rate limiter and the bounded link cache), `crates/tenko-scan/src/sd/source/**` (the exchange client on the probe, reporting heard records and learn summaries, executing `Ask` and the refresh queries of section 2.5, the flow test executor of section 2.13), the move of the scanner's mDNS parsing and passive listener onto it (`crates/tenko-scan/src/dns/message.rs`, `dns/mdns.rs`, `methods/names.rs`) with every existing fixture test still passing, `fuzz/fuzz_targets/mdns_message.rs` (and the hook in `scan_dns_message.rs`), the fixtures of section 3.5 with WP17.6.
- **Depends on:** WP17.0.
- **Content:** first, the builder confirms on the lab's kernel whether `SO_BINDTODEVICE` needs `CAP_NET_RAW` and records it in the module's documentation.
- **Acceptance:** E100, E101; E106's source half (the limiter and the cache under the flood); E113's probe half.

#### WP17.2 The controller: policy, the service table, learn mode and flows (6 builder-days)

- **Requirements:** DNS-35, IPAM-12.
- **Owns:** `crates/tenko-scan/src/sd/control/**` (the exchange server with the binding of events to the sending node, the strict re-validation, the policy engine, the refusal of names the destination link uses and of lookalike names, the writer of `sd.services` with its rate and `valid_until`, the fan-out to destination probes, learn mode, the ingest of `Observed::Service` facts, the findings, the flow catalog and the test orchestration), `crates/tenko-scan/data/sd-flows.toml`, `crates/tenko-api/src/routes/sd/**`, `crates/tenko/src/cli/sd*`, `fuzz/fuzz_targets/sd_exchange.rs`.
- **Depends on:** WP17.0; parallel to WP17.1 (the exchange is tested with recorded `ProbeEvent` messages).
- **Content:** the flow catalog's entries are read from the vendors' public documentation, each with the source and the date; an entry that cannot be confirmed is left out.
- **Acceptance:** E102, E109 (the store half), E113's controller half; the route tests of [api/README.md](../api/README.md).

#### WP17.3 The gateway's destination side on the probe (7 builder-days)

- **Requirements:** DNS-35.
- **Owns:** `crates/tenko-scan/src/sd/gateway/**` (the responder: probing, announcing, answering with the delays, known-answer and duplicate suppression, QU and legacy unicast, synthesized NSEC, goodbyes; interests for questions it cannot answer fresh; the loop guards; the send bounds; repeater detection; conflict yielding and the hourly re-probing; the behavior without the controller and at stop), its hooks in WP17.1's exchange client, the wiring in the probe's serve path (with the lead).
- **Depends on:** WP17.1 and WP17.2.
- **Acceptance:** E103, E104, E105, E106, E107 in the lab of WP17.6; unit tests of every row of section 2.4's table against recorded packets.

#### WP17.4 The Discovery Proxy in the DNS server (6 builder-days)

- **Requirements:** DNS-35, DNS-20.
- **Owns:** `crates/tenko-dns/src/sd/**` (the synthesized zone kind and its snapshot built from `sd.services`, the rich-text and LDH subdomains, the name rewriting and address suppression, SOA and NS, the delegation in the parent zone's snapshot and transfers, the browsing names in the search-domain and reverse zones, the derived ACL and the forwarder finding, the answers of RFC 8766 sections 6.3 and 6.4, the bounded interest queue), the zone kind's hook in the serving path (with the lead: a shared hot path), the rows of [CONFORMANCE.md](../CONFORMANCE.md) for RFC 6762, 6763, 8766 and 8765, a section of [dns.md](../dns.md), `bench/sd/proxy/**` (M80).
- **Depends on:** WP17.0 for everything tested against fixture rows; WP17.2 for the interest's path to the controller, end to end. Parallel to WP17.1 to WP17.3.
- **Acceptance:** E108; the query path's no-allocation test with the new zone kind; M80.

#### WP17.5 The UI and the host view (5 builder-days)

- **Requirements:** DNS-35.
- **Owns:** `ui/src/discovery/services/**` (links with their prefixes and learn mode; the learn view with "Allow"; rules as a list and as a matrix of ordered pairs; the services that cross, by link and by device; flows with the copyable text and the test), `ui/src/hosts/HostServices.tsx` and its one line in `HostView.tsx` (with the lead), the mock API, the texts in English and Swedish; Playwright tests.
- **Depends on:** WP17.2's routes (the mock first).
- **Acceptance:** E109 (the view), E110.

#### WP17.6 The lab, the security rows, the measurements and the check list (6 builder-days, plus the owner's hour)

- **Requirements:** DNS-35.
- **Owns:** `deploy/compose/lab-mdns/**`, the rows below in `deploy/security/`, `bench/sd/**` except `bench/sd/proxy/` (M77 to M79 and the owner's check), `docs/service-discovery.md` (the operator's page), `docs/plans/discovery-exit.md`, the owner's check list as `deploy/compose/lab-mdns/owner-check.md`.
- **Depends on:** WP17.0 for the lab skeleton; WP17.3 and WP17.4 for the rounds.
- **The lab** (no device of the owner needed): bridge networks `servers` (`198.51.100.0/24`), `lan` (`192.0.2.0/26`, `2001:db8:10::/64`) and `iot` (`192.0.2.64/26`, `2001:db8:11::/64`); containers `controller` (`tenko:lab`, roles `controller,dns`), `probe-lan` and `probe-iot` (`tenko:lab`, role `probe`, each on its segment and on `servers`), `router` (joined to `lan` and `iot`, forwarding with an `nftables` rule set that allows one flow and drops another, for the flow test), `responder` on `iot` (Avahi publishing a printer and a receiver with `avahi-publish`, and python-zeroconf for scripted announcements, goodbyes, conflicts and TXT changes), `browser` on `lan` (`avahi-browse`, a python-zeroconf browser, `dig`), `local` on `lan` (a host that claims a carried name, for E104), `reflector` (Avahi with `enable-reflector=yes`, joined to both, for E105, in its own compose profile), `flood` on `iot` (a Python script with plain sockets that builds the hostile packets of E106; no packet tool is installed) and `capture` (`tcpdump`, writing the captures that become the fixtures of section 3.5). The images are built from `debian:13-slim` with the Debian packages `avahi-daemon`, `avahi-utils`, `python3-zeroconf`, `dnsutils`, `tcpdump` and `nftables`; Avahi runs with `enable-dbus=no` **(unconfirmed that the publishing tools work without D-Bus; if not, the image starts `dbus-daemon`)**. Multicast between containers of one bridge network works without configuration (the bridge floods it). The script is `smoke.sh` with rounds `gateway`, `proxy`, `loops`, `flood`, `outage`, `flows`, printing PASS, FAIL and SKIP lines as the other labs do.
- **The rows:**

  | Row | What is checked |
  |---|---|
  | `sd.off_by_default` | A fresh installation of each profile carries nothing and answers no proxy subdomain |
  | `sd.direction` | A rule `iot` to `lan` carries nothing from `lan` to `iot`, through the gateway and the proxy |
  | `sd.attribution` | Off-link address records and announcements for another device's address are not carried |
  | `sd.no_defense` | No packet from a probe answers another host's probe for a carried name (capture grep) |
  | `sd.bounds` | The flood round: every bound of section 2.8 holds; the probe stays up |
  | `sd.proxy_acl` | A client outside the derived ACL is refused for the subdomain and for the browsing names |
  | `sd.hardened` | Under Hardened: a rule without devices, or without the step-up, refused; learn mode refused to an operator |
  | `sd.privacy` | No TXT value and no instance name in a log line or in the store outside `sd.services` and the service facts (grep over the round's captures and a dump of the store) |
  | `sd.no_firewall_change` | No packet from Tenko is addressed to the router's own addresses; the only packets the router forwards from Tenko are the flow test's connections (capture) |
  | `sd.foreign_link` | A probe whose exchange names a link of another node is refused and the finding raised |

- **Acceptance:** E105, E106, E111, E113 (the lab round); E112 (owner-run).

Total: 41 builder-days. The gateway first: WP17.0, then WP17.1 and WP17.2 in parallel, WP17.3, WP17.6 (24 days on the critical path). The Discovery Proxy first: WP17.0, then WP17.1, WP17.2 and WP17.4 in parallel, then WP17.6's proxy round (17 days). WP17.5 runs beside either from the mock.

## 5. Order, measurements and exit checks

### 5.1 Order

WP17.0 first. Then WP17.1, WP17.2 and WP17.4 in parallel (disjoint files: `tenko-scan/src/mdns` with `tenko-scan/src/sd/source`, `tenko-scan/src/sd/control` with the API and CLI, `tenko-dns/src/sd`). Then WP17.3. WP17.5 follows the routes over the mock; WP17.6 builds the lab skeleton after WP17.0 and runs its rounds as WP17.3 and WP17.4 land. The two parts are separable: the gateway alone is WP17.0 to WP17.3, WP17.5 without the proxy pages and WP17.6 without the proxy round; the proxy alone is WP17.0, WP17.1 (the listener, the cache and the source side), WP17.2, WP17.4, and WP17.6's proxy round. DNS-35 is no condition of 0.1.0 (ROADMAP), so the slice takes a builder slot only when one is free (SD-Q14). WP17.0 and WP17.1 with learn mode are useful alone: they show what each segment announces before anything is decided about crossing.

### 5.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M77 | Resident memory of a probe with two links, every bound of section 2.8 filled by the flood generator, and with a typical home load (100 instances, 300 records) | Growth over the idle probe at most 32 MiB filled, at most 4 MiB typical | WP17.6 |
| M78 | CPU of the same probe at 200 packets per second heard per link for 10 minutes | At most 5 percent of one core of the reference VM; p99 from arrival to decision under 1 ms | WP17.6 |
| M79 | From an announcement on `iot` to the first announcement on `lan`, new names and changed records, 100 samples each | New name p99 under 1.5 s; changed record p99 under 300 ms | WP17.6 |
| M80 | The Discovery Proxy: snapshot build from 512 instances, and the query rate for proxy names against the rate for an ordinary zone on the same node | Build under 50 ms; query rate within 5 percent | WP17.4 |

## 6. Owner decisions

Each question lists its options, the trade-offs in the owner's order (security, performance, usability, features) and one recommendation.

**SD-Q1. How do announcements travel from one segment's probe to the other's?**
- Options: (a) as validated, normalized records through the controller and the store (section 2.2); (b) directly between the two probes over a new mTLS connection; (c) only within one probe that has an interface on both segments, as a repeater does.
- Trade-offs: security: (a) has one place that checks every record against the rules and audits, and opens no new port on the probes; (b) needs each probe to accept inbound connections and a firewall opening between the segments for Tenko itself, and splits enforcement between the probes; (c) puts one process on both sides of the boundary, the position of a plain repeater. Performance: (a) adds a local hop and a store write per change (not per refresh), a few milliseconds in a home; (b) and (c) are faster. Usability: (a) works with the probes as they are enrolled today and across controllers in a cluster. Features: equal.
- **Recommendation: (a).**

**SD-Q2. Under which names does the gateway announce what it carries, and what does it do about name conflicts?**
- Options: (a) the original names, probing before first use, and the host of the destination link always wins: the gateway never defends a carried name, never renames, and withdraws on conflict with a finding; (b) names renamed with a suffix per link (`Printer (iot)`, `printer-iot.local`), which avoids conflicts; (c) the original names without probing.
- Trade-offs: security: (a) gives a device on the untrusted segment no way to make a trusted device lose its name; (c) breaks RFC 6762 section 8 and lets carried records fight local owners; (b) is safe for names but hides the original name from the user. Usability and features: (b) changes names that some protocols treat as identity (Matter's operational instance names encode the fabric and the node; renaming breaks them), and users see unfamiliar names; (a) keeps every client working as on one link.
- **Recommendation: (a).**

**SD-Q3. Which devices' announcements may cross?**
- Options: (a) a rule names its devices; under Home and Standard a rule may say "any device of the source link", and each device that starts crossing raises a finding; under Hardened devices must be listed; (b) by service type only, everywhere; (c) devices always listed, in every profile.
- Trade-offs: security: (c) is tightest; (b) lets any new device on the untrusted segment appear on the trusted one under a listed type, silently; (a) makes that visible and forbids it under Hardened. Usability: (c) makes a home owner edit a rule for every new casting device; (a) keeps the home case one rule.
- **Recommendation: (a).**

**SD-Q4. Must an announcement point at the device that sent it?**
- Options: (a) yes: the addresses in the announcement must be on the source link and include the sender's own address; announcements for other on-link addresses (a sleep proxy, a hub or border router announcing the devices behind it) only when the rule allows it, for named prefixes; (b) the addresses must be on the source link, any sender; (c) no check.
- Trade-offs: security: (c) lets any device send clients anywhere; (b) lets one device on the link redirect clients to another device of the same link; (a) bounds a device to its own services. Features: (a) needs a per-rule exception for hubs and Thread border routers (Matter devices behind them), off by default.
- **Recommendation: (a).**

**SD-Q5. What does the destination probe do when it loses the controller?**
- Options: (a) keep its policy, carry nothing new, let what it carries expire at its own TTL without goodbyes, and resynchronize when the controller returns; (b) send goodbyes for everything at once; (c) keep announcing what it has until the controller returns.
- Trade-offs: security: (c) can keep a revoked or vanished service alive indefinitely; (a) bounds that to the record's TTL (2 minutes for the addresses and the SRV record a client needs to connect, 75 minutes for the PTR and TXT records that keep the service listed); (b) has no such window. Usability: (b) makes every casting device disappear from every phone during a controller restart or an upgrade; (a) rides through short outages.
- **Recommendation: (a).**

**SD-Q6. May one probe serve two links (one VM with an interface on each VLAN)?**
- Options: (a) yes, with the records still going through the controller, and refused under Hardened for the two links of one pair; (b) never: one link per probe; (c) yes, in every profile.
- Trade-offs: security: a probe with both links of a pair puts one process on both sides of the boundary, so a flaw in its handling of packets from the untrusted segment would reach the trusted one; (b) avoids that; (a) refuses it where the profile asks for it. Usability: many home installations run one VM, and a second probe is a second VM or device to maintain.
- **Recommendation: (a).**

**SD-Q7. Where do the Discovery Proxy's answers come from?**
- Options: (a) from the service table only: a miss answers at once with no records (negative TTL 10 s) and asks the source probe to query, and links with the proxy keep the listed types fresh; a recorded deviation from RFC 8766 section 5.6; (b) the RFC's timing: hold the client's query up to 6 s while the probe asks on the link; (c) run the proxy on the probe of the link itself, answering unicast DNS there.
- Trade-offs: security: (c) makes clients of the trusted segment send DNS to a probe on the untrusted one and opens port 53 into it. Performance: (b) needs a deferred-answer path in a query path that today reads memory only and never waits; (a) keeps that path. Usability: (a) can return an empty first answer after a cold start, which the client's next query, within 10 s, corrects.
- **Recommendation: (a).**

**SD-Q8. DNS Push and Long-Lived Queries for the proxy?**
- Options: (a) out of this slice: the names that announce them answer as absent, and Push comes later with DNS Stateful Operations; (b) DNS Push now.
- Trade-offs: security and performance: Push needs long-lived TLS sessions with state per client in the DNS server, a new path with its own bounds and fuzzing; usability: Push gives instant updates to the clients that support it, but ordinary queries with a TTL of 10 s work for all of them.
- **Recommendation: (a).**

**SD-Q9. The names of the proxy's subdomains and how clients find them?**
- Options: (a) under a parent `sd.<search domain>` (for example `sd.example.test`), a rich-text subdomain per link for the services, named with the link's display name (`IoT devices.sd.example.test`), and an LDH subdomain for host names (`iot.sd.example.test`), one subdomain when the display name is an LDH label; the browsing names (`b`, `db`, `lb` under `_dns-sd._udp`) answered in the destination link's search-domain zones and in the reverse zone of the client's network; (b) the LDH subdomain only; (c) a zone outside the internal names.
- Trade-offs: security: equal, the ACL of SD-Q10 applies to each. Usability: (a) needs no new DHCP option, uses the search domain the clients already have, and shows the link's own name in the client's browser; (b) is simpler, but RFC 8766 section 5.3 says a proxy MUST NOT offer only an LDH subdomain, so it would be a deviation; (c) needs a search domain clients do not have.
- **Recommendation: (a), with the display name defaulting to the LDH label, so that a site that sets nothing has one subdomain.**

**SD-Q10. Who may query the proxy's subdomains?**
- Options: (a) only clients whose address is in a destination link of a rule that allows the proxy, derived from the rules, with an optional narrower ACL by the operator; (b) every client that can query the DNS server.
- Trade-offs: security: (b) lists the untrusted segment's devices to any client, including those on the untrusted segment itself and on guest networks (RFC 8766 section 9.2 warns of exactly this); (a) follows the direction of the rules. Usability: (a) needs no setting.
- **Recommendation: (a).**

**SD-Q11. What does Tenko keep about the services it sees?**
- Options: (a) for instances a rule names: type, port, instance name, host name, the TXT key names and size (never a value), as observation facts with their 30-day retention; for the rest, nothing beyond learn mode's memory; no names in logs; under Hardened names visible to `sd.read` holders only, with the site's shortest personal-data retention; (b) everything heard, TXT values included; (c) type and port only.
- Trade-offs: security (privacy): instance names often carry people's names and TXT values carry identifiers (RFC 8882); (b) builds a register of who is present; (c) leaves the host view unable to say which instance crosses. Usability: (a) shows the operator what crosses and from whom.
- **Recommendation: (a).**

**SD-Q12. What does Tenko do about the firewall?**
- Options: (a) list the flows a client needs per carried device (the SRV port, plus a catalog of further flows per service type read from the vendors' documentation), test reachability from the destination probe under the active-probing toggle, and never change a firewall; (b) list only, no test; (c) nothing.
- Trade-offs: security: every option leaves the firewall to the operator; the test is an active probe and follows TGL-18 (off under Hardened unless enabled for the segment). Usability: (c) leaves a discovered but blocked service unexplained; (a) says what to allow and whether it passes.
- **Recommendation: (a).**

**SD-Q13. The defaults and the Hardened profile?**
- Options: (a) off in every profile; under Home and Standard the network operator may enable it; under Hardened only an administrator, per ordered pair, with the passkey step-up, devices listed, no announcements for others, learn mode for administrators only, the proxy's ACL as derived, no probe with both links of a pair; (b) not available under Hardened.
- Trade-offs: security: (b) is simplest; (a) keeps every crossing explicit, attributed and reviewed. Usability: (b) pushes Hardened sites back to the firewall's repeater, which carries everything unchecked.
- **Recommendation: (a).**

**SD-Q14. Which part first, and when?**
- Options: (a) the gateway first, the proxy second, in a free builder slot after the 0.1.0 work, with WP17.0 and WP17.1 (learn mode) as a first step; (b) the proxy first; (c) both together.
- Trade-offs: usability: the clients of the case (casting apps, most home-automation apps, Android) discover by mDNS only; the clients that browse by unicast DNS (macOS and iOS, Linux with Avahi, some printing systems) are fewer, so (b) serves fewer of them first. Performance and security: equal. Features: (c) is the whole requirement soonest, at twice the builder slots.
- **Recommendation: (a).**

## 7. Requirement rows touched

No new requirement IDs. Proposed edits, applied with the decisions:

| Row | Today | Proposed |
|---|---|---|
| DNS-35 | "... only the listed service types and devices cross ..." | Adds: "What crosses is validated records, never packets; announcements carry the original names, and a host of the destination link always keeps its name. Tenko lists the flows the firewall must allow and never changes a firewall." |
| SCAN-02 | "Passive discovery first: ARP/NDP, mDNS and LLDP." | Unchanged; the scanning document notes that the mDNS listener joins both groups per interface |

[CONFORMANCE.md](../CONFORMANCE.md): 6762 stays Partial with the gateway's behavior and its deliberate deviations (never defends, withdraws instead of renaming after a conflict, accepts multicast packets only from sources inside the link's prefixes or link-local); 6763 notes the browsing names served; 8766 becomes Partial with the deviations of section 2.10 (cache-only answers with an interest on a miss, no reverse mapping, no DNSSEC, no LLQ or Push, no browsing names under `.local`); a new row for 8765 as Not planned in this slice. ROADMAP: the Phase 4 line for DNS-35 links this plan. SECURITY-PROFILES.md: the two toggles of section 3.4.

## 8. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R175 | The namespace `sd` needs data format 7, which the public DNS plan's namespace may take first | WP17.0 decides first, with the lead; an empty migration with its fixture, as earlier formats; whichever slice lands second shares the version or takes the next |
| R176 | A client app discards a service whose address is not on its own link | The lab cannot show it; the owner's check list (section 9.2) does, per device category; the finding points to the Discovery Proxy or to a probe with both links where the profile allows |
| R177 | A legitimate device announces faster than the bound (some firmware repeats announcements) and is muted | The mute is per device for 60 s with a finding naming it; a rule may raise the bound for its devices up to twice the default |
| R178 | Hubs and Thread border routers announce for devices behind them, which the attribution rule refuses | The per-rule exception with named prefixes (SD-Q4), shown in learn mode as "announces for other addresses" |
| R179 | Devices with only link-local addresses cannot be reached from another segment at all | Not carried, with `sd.no_routable_address` in learn mode; nothing Tenko can fix |
| R180 | The firewall's repeater stays on beside the gateway | Duplicate answer suppression keeps it harmless; `sd.repeater_detected` and the operator's page say to turn it off |
| R181 | A compromised probe invents records for its link | The rules, the bounds and the controller's re-validation are the boundary (section 2.14); the plan does not claim more |
| R182 | Instance names and TXT values are personal data | Section 2.12; the `sd.privacy` row |
| R183 | Users blame Tenko when the firewall blocks a discovered service | The flows view, the reachability test and `sd.flow_blocked` |
| R184 | Another mDNS responder or repeater on the probe's host (Avahi, a resolver with mDNS) shares port 5353 and reflects or answers | The operator's page says to turn reflection off on the probe's host; a probe drops packets from its own host's addresses; learn mode shows the host's own services as such |
| R185 | The cache-only proxy answers empty after a cold start | The negative TTL of 10 s and the refresh browsing of section 2.10; measured in E108's round as the time from start to the first full answer |
| R186 | Exit criteria E100 onward are not traced until the trace script accepts three digits | WP17.0 widens the pattern (section 1.2) |
| R187 | Vendor flows of the firewall catalog are wrong or change | Each entry carries its source and date; an entry that cannot be confirmed is left out; the test checks the SRV port, which is always right |
| R188 | Lookalike names (confusable characters beyond case and width) pass the check of section 2.4 | Format and bidirectional characters are refused; a full confusable check needs Unicode's data table, for which WP17.2 presents a crate and our own small table side by side to the owner before adding either |
| R189 | An intrusion detection system on the destination segment reads the gateway's answers for other hosts' names as mDNS spoofing | The operator's page names the probe's addresses to exempt; scanning.md is corrected (section 10) |
| R190 | Clients of the destination segments query through a forwarder that serves several segments, so the proxy's ACL cannot tell them apart | `sd.proxy_forwarder`; the operator's page says the destination clients must ask Tenko directly (section 2.10) |

## 9. Owner actions and the check list with real devices

### 9.1 Owner actions

| When | Action |
|---|---|
| Before WP17.0 | Decide SD-Q1 to SD-Q14 |
| Before the check list | Place a probe on the untrusted segment (a small VM or device with the `probe` role and its drop-in), or give the existing node an interface on it if SD-Q6 allows |
| Before the check list | Note which of the firewall's mDNS repeater settings are on; turn the repeater off for the pair under test during the check |
| During the check list | Allow on the firewall the flows the flows view lists for the devices under test, and nothing wider |

### 9.2 The check list, step by step

The results are recorded in `bench/sd/results/<date>-owner-check.md` with device categories only ("casting device A", "network printer", "home-automation hub", "phone, mobile OS 1", "laptop, desktop OS 2"), never a device name, an instance name, a host name, an address outside the documentation ranges, or a vendor account. For each step note PASS, FAIL or NOT TESTED, with one line on what was seen.

1. **Learn.** Turn learn mode on for the untrusted link for an hour. *Check:* every device of the segment that announces appears with its types; nothing appeared on the trusted segment (a browser app on a phone there finds none of them).
2. **One rule, one device.** Allow the printer's type (`_ipp._tcp`, and `_ipps._tcp` if listed) from the untrusted to the trusted link for the printer only. *Check:* a laptop and a phone on the trusted segment list the printer within a few seconds; the flows view lists TCP 631 to the printer; after allowing that flow, a test page prints.
3. **The casting device.** Allow the casting device's type for that device. *Check:* the phone's casting app lists it; casting a video works; if not, the flows view and its test say which flow fails, and the result says which flows had to be allowed.
4. **Direction.** *Check:* on the untrusted segment, a browser app (or the learn view of the trusted link) shows none of the trusted segment's services.
5. **A home-automation device**, if one discovers by mDNS: the same as step 3.
6. **Restart the controller.** *Check:* the devices stay listed on the phone during the restart, and casting still starts afterwards.
7. **Remove the rules.** *Check:* within a few seconds the devices disappear from the phone's lists.
8. **The Discovery Proxy**, if built: with the proxy enabled for the printer's rule, on a laptop whose system browses by unicast DNS: *Check:* the printer is listed under the untrusted link's subdomain, and `dig PTR _ipp._tcp.<label>.sd.<search domain>` from the laptop answers; from a host on the untrusted segment the same query is refused.
9. **Restore.** Turn the firewall's repeater back on if it was on before, or leave it off and keep the rules; note which.

**To undo at any point:** delete the rules or turn the toggle off; carried records disappear at once (goodbyes) from the trusted segment. The firewall was changed only by the owner.

## 10. Documents this slice writes

| Document | Package |
|---|---|
| The ADR for service discovery across segments (proposed 0037) | WP17.0 |
| [SECURITY-PROFILES.md](../SECURITY-PROFILES.md): the two toggles | WP17.0 |
| `scripts/requirement-trace.mjs`: three-digit exit criteria, this plan in the Phase 4 list | WP17.0 (with the lead) |
| [scanning.md](../scanning.md): the link listener, IPv6 and per-interface reception; section 2.5 and its table for intrusion detection systems, which say that Tenko never answers or announces, corrected for a probe with a link (the gateway answers for other hosts' names, which such a system can read as mDNS spoofing) | WP17.1 |
| [node-sync.md](../node-sync.md): the `ServiceDiscovery.Exchange` stream | WP17.2 |
| [reconciliation.md](../reconciliation.md): the `Observed::Service` fact | WP17.2 |
| [dns.md](../dns.md): the Discovery Proxy's zones, names and ACL | WP17.4 |
| [CONFORMANCE.md](../CONFORMANCE.md): rows 6762, 6763, 8766 and 8765 | WP17.4 |
| `docs/service-discovery.md`: the operator's page (links, learn mode, rules, the firewall, the firewall's repeater, the check list as a runbook) | WP17.6 |
| `bench/sd/` with M77 to M80 and the owner's check | WP17.4, WP17.6 |
| `docs/plans/discovery-exit.md` | WP17.6 |

**The trace.** This plan names DNS-35 and other Phase 1 to 4 rows; the trace files are regenerated with it (`node scripts/requirement-trace.mjs` and its `--phase` variants).

## 11. Sources

The facts about Tenko come from the code and the documents read on `cbe6c27a` (section 1.5). The pages below were read on 2026-11-11:

- RFC 6762, Multicast DNS (sections 3, 5.1, 5.4, 5.5, 6, 6.1, 6.2, 6.4, 6.7, 7.1 to 7.4, 8.1 to 8.3, 9, 10, 10.1, 10.2, 11, 14, 17, 18.12, 18.13, 20 and 21: source address and IP TTL rules, the two uses of the class field's top bit, known-answer and duplicate suppression, probing, announcing, conflicts, goodbyes, TTLs, sizes, rates and delays, NSEC, multiple interfaces and IPv6): https://www.rfc-editor.org/rfc/rfc6762.html
- RFC 6763, DNS-Based Service Discovery (sections 4, 6, 7.1, 9 and 11: instance names, TXT size, subtypes, the type list, browsing domains and the address-derived names): https://www.rfc-editor.org/rfc/rfc6763.html
- RFC 8766, Discovery Proxy for Multicast DNS-Based Service Discovery (sections 2, 3, 5.1 to 5.6, 6.1, 6.2, 6.4, 7, 8 and 9: the subdomain per link, the LDH host names, name rewriting, address suppression, the TTL of 10 s, timing of answers, SOA values, the Push and LLQ names, DNSSEC, IPv4 and IPv6, security and the rate of 20 queries per second): https://www.rfc-editor.org/rfc/rfc8766.html
- RFC 8765, DNS Push Notifications, and RFC 8490, DNS Stateful Operations (what Push would need: DSO over TLS, the `_dns-push-tls._tcp` lookup): https://www.rfc-editor.org/rfc/rfc8765.html and https://www.rfc-editor.org/rfc/rfc8490.html
- RFC 7558, Requirements for Scalable DNS-SD/mDNS Extensions (the requirements this design answers, among them per-service control over what leaves a link): https://www.rfc-editor.org/rfc/rfc7558.html
- RFC 8882, DNS-SD Privacy and Security Requirements (instance names as a leak of presence): https://www.rfc-editor.org/rfc/rfc8882.html
- RFC 9665, Service Registration Protocol, and the Advertising Proxy Internet-Draft (left out, section 1.4): https://www.rfc-editor.org/rfc/rfc9665.html and https://datatracker.ietf.org/doc/draft-ietf-dnssd-advertising-proxy/
- avahi-daemon.conf(5) (the reflector, `reflect-filters`, `check-response-ttl`, the interface lists): https://manpages.debian.org/bookworm/avahi-daemon/avahi-daemon.conf.5.en.html
- The small repeater daemon (copies packets between interfaces from its own address, no filter): https://github.com/geekman/mdns-repeater
- Debian packages for the lab (`avahi-daemon`, `avahi-utils`, `python3-zeroconf`): https://packages.debian.org/sid/avahi-utils and https://packages.debian.org/trixie/python3-zeroconf
- The repeater documentation of two open-source firewall distributions and of a prosumer network controller was read for what their repeaters filter (one by service type, the others by interface only); they are product categories here, not named.

**Unconfirmed on 2026-11-11**, for the packages to settle: whether `SO_BINDTODEVICE` needs `CAP_NET_RAW` on the probe's kernel (WP17.1); the further flows per service type for the firewall catalog (WP17.2); whether Avahi's publishing tools work with `enable-dbus=no` in the lab image (WP17.6); how a client app behaves with a service whose address is on another segment (the owner's check list).

Specifications also used: RFC 1035 (DNS names), RFC 3397 (DHCP domain search), RFC 3927 (IPv4 link-local addresses), RFC 4193 (unique local IPv6 addresses), RFC 5737 and RFC 3849 (documentation addresses).

Project documents: [cluster.md](../cluster.md), [node-sync.md](../node-sync.md), [scanning.md](../scanning.md), [reconciliation.md](../reconciliation.md), [dns.md](../dns.md) sections 11 and 12, [dhcp.md](../dhcp.md) section 4, [SECURITY-PROFILES.md](../SECURITY-PROFILES.md), ADR 0004, ADR 0009, ADR 0017, ADR 0023, ADR 0031, [public-dns-plan.md](public-dns-plan.md).
