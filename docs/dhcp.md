# DHCP

This page describes how Tenko DDI configures DHCP, reads and writes DHCP messages and, as Phase 3 lands, how the `dhcp` role serves them. It is for operators who set up scopes, pools and options, for builders of the DHCP server, and for those who want to know what a node accepts on the wire. Section 1 describes the DHCPv4 wire codec in `crates/tenko-dhcp` (`tenko_dhcp::v4`); sections 2 to 7 the configuration: the model, scopes and pools, options and the catalog, classes and policies, MAC filters, and the API and command line (`tenko_dhcp::config` and the `/dhcp` routes). Where this page and the code differ, the code is right. The requirements are DHCP-01 to DHCP-08 and DHCP-13 in [REQUIREMENTS.md](REQUIREMENTS.md); the RFCs and their status are in [CONFORMANCE.md](CONFORMANCE.md); the contracts every Phase 3 package builds on are in [dhcp-contracts.md](dhcp-contracts.md).

Contents:

1. [The wire format](#1-the-wire-format)
8. [Leases](#8-leases)
9. [The engine](#9-the-engine)
10. [The role](#10-the-role)
12. [Reservations, the move step and observations](#12-reservations-the-move-step-and-observations)
13. [DDNS](#13-ddns)
2. [The model](#2-the-model)
3. [Scopes and pools](#3-scopes-and-pools)
4. [Options and the catalog](#4-options-and-the-catalog)
5. [Classes and policies](#5-classes-and-policies)
6. [MAC filters](#6-mac-filters)
7. [The API and the command line](#7-the-api-and-the-command-line)
14. [Conflict detection and DECLINE](#14-conflict-detection-and-decline)
16. [Classes, policies, PXE and UEFI](#16-classes-policies-pxe-and-uefi)
15. [Fingerprinting and the reconciliation view](#15-fingerprinting-and-the-reconciliation-view)
17. [The home cut-over](#17-the-home-cut-over)
18. [The Kea export](#18-the-kea-export)
19. [DHCPv6](#19-dhcpv6)

## 1. The wire format

The codec reads a received DHCPv4 message as a view over the datagram's buffer and writes a reply into a buffer the caller owns. Neither side allocates, in the style of the DNS codec ([dns.md, section 12](dns.md#12-the-engine)): the server keeps one receive buffer and one reply buffer per worker, and `crates/tenko-dhcp/tests/alloc.rs` fails when parsing, reading an option or building a reply allocates. The codec has no sockets, no lease logic and no store; it is the layer the server is built on.

### 1.1 The view

`Message::parse` accepts a datagram of at least 240 octets: the 236 octets of the fixed header of RFC 2131, section 2, and the magic cookie `63 82 53 63`. Nothing else is checked when the message is parsed; the fields and the options are read from the buffer when the server asks for them.

| Field | Accessor | Notes |
|---|---|---|
| `op`, `htype`, `hlen`, `hops` | `op()`, `htype()`, `hlen()`, `hops()` | `op` 1 is BOOTREQUEST, 2 BOOTREPLY |
| `xid`, `secs` | `xid()`, `secs()` | |
| `flags` | `flags()`, `broadcast()` | The broadcast bit is 0x8000 |
| `ciaddr`, `yiaddr`, `siaddr`, `giaddr` | the same names, as `Ipv4Addr` | |
| `chaddr` | `chaddr()`, `mac()`, `chaddr_field()` | `chaddr()` is the first `hlen` octets (an error above 16); `mac()` is the Ethernet address and an error unless `htype` is 1 and `hlen` 6; `chaddr_field()` is all 16 octets |
| `sname`, `file` | `server_name()`, `boot_file()` and their `_str` forms; `sname_field()`, `file_field()` | The name up to its zero octet, or `None` when option 52 lends the field to options; an error when a malformed option in the options field hides whether option 52 is there; the `_field` forms are the raw octets |

### 1.2 The option areas and overload

Options live in up to three areas. `Message::options()` walks them in the order of RFC 2131, section 4.1, and yields every instance with its code, its value and the area it came from:

1. the options field after the magic cookie, up to the end option or the end of the datagram;
2. `file`, when option 52 (RFC 2132, section 9.3) has the value 1 or 3;
3. `sname`, when option 52 has the value 2 or 3.

Option 52 is only read in the options field; an instance in `file` or `sname` is yielded but changes nothing. Pad (0) is skipped and end (255) ends its area. An options field without an end option ends at the end of the datagram, which many clients rely on; octets after the end option are padding and not read.

### 1.3 Split options (RFC 3396)

An option longer than 255 octets is sent as several instances of the same code, which the receiver joins in the order of the walk: the options field, then `file`, then `sname`. Clients also split shorter options, the domain search list of RFC 3397 above all. The codec handles this in two steps, so that the common reads never copy:

- The typed accessors read the one instance of an option. When the message carries several instances of it they return `DecodeError::Split`.
- `Message::option_data(code, &mut buf)` joins every instance into the caller's buffer and returns the joined value (one instance is returned from the message itself, without a copy). The type's `parse` then reads it: `DomainSearch::parse(message.option_data(119, &mut buf)?)`.

The builder splits on its side (section 1.5).

### 1.4 The typed options

Every typed value is a view that checks its format once in `parse` and then reads without failing. A value with the wrong length or format returns `DecodeError::BadLength` or `DecodeError::BadValue` with the option code; the walk and the other options are not affected.

| Code | Option | RFC | Read as | Written by |
|---|---|---|---|---|
| 1 | Subnet mask | 2132, 3.3 | `subnet_mask()`: `Ipv4Addr` | `subnet_mask` |
| 3 | Routers | 2132, 3.5 | `routers()`: `AddrList` | `routers` |
| 6 | Domain name servers | 2132, 3.8 | `domain_name_servers()`: `AddrList` | `domain_name_servers` |
| 12 | Host name | 2132, 3.14 | `host_name()`: octets | `host_name` |
| 15 | Domain name | 2132, 3.17 | `domain_name()`: octets | `domain_name` |
| 26 | Interface MTU | 2132, 5.1 | `interface_mtu()`: `u16` | `interface_mtu` |
| 28 | Broadcast address | 2132, 5.3 | `broadcast_address()`: `Ipv4Addr` | `broadcast_address` |
| 42 | NTP servers | 2132, 8.3 | `ntp_servers()`: `AddrList` | `ntp_servers` |
| 43 | Vendor-specific information | 2132, 8.4 | `vendor_specific()`: octets | `vendor_specific` (raw) |
| 50 | Requested IP address | 2132, 9.1 | `requested_address()`: `Ipv4Addr` | |
| 51 | Lease time | 2132, 9.2 | `lease_time()`: `u32` seconds | `lease_time` |
| 52 | Overload | 2132, 9.3 | `overload()`: 0 to 3 | the builder itself |
| 53 | Message type | 2132, 9.6 | `message_type()`: `MessageType` | `message_type`, first in every reply |
| 54 | Server identifier | 2132, 9.7 | `server_identifier()`: `Ipv4Addr` | `server_identifier` |
| 55 | Parameter request list | 2132, 9.8 | `parameter_request_list()`: the codes | |
| 57 | Maximum message size | 2132, 9.10 | `max_message_size()`: `u16`; `max_reply_len()` | |
| 58, 59 | Renewal (T1) and rebinding (T2) time | 2132, 9.11, 9.12 | `renewal_time()`, `rebinding_time()`: `u32` | `renewal_time`, `rebinding_time` |
| 60 | Vendor class identifier | 2132, 9.13 | `vendor_class_identifier()`: octets | `vendor_class_identifier` (`PXEClient`) |
| 61 | Client identifier | 2132, 9.14; 4361 | `client_identifier()`: `ClientId` | |
| 66, 67 | TFTP server name, boot file name | 2132, 9.4, 9.5 | `tftp_server_name()`, `bootfile_name()` | `tftp_server_name`, `bootfile_name` |
| 77 | User class | 3004 | `user_class()`: `UserClass` | |
| 81 | Client FQDN | 4702 | `client_fqdn()`: `ClientFqdn` | `client_fqdn` |
| 82 | Relay agent information | 3046; 3527, 3993, 5107, 6925 | `relay_agent_info()`: `RelayAgentInfo` | `relay_agent_info` (echoed) |
| 93 | Client system architecture | 4578, 2.1 | `client_architectures()`: `Architectures` | |
| 94 | Client network interface identifier | 4578, 2.2 | `network_interface()`: `NetworkInterfaceId` | |
| 97 | Client machine identifier | 4578, 2.3 | `machine_id()`: `MachineId` | |
| 116 | Auto-configure | 2563 | `auto_configure()`: `u8` | |
| 118 | Subnet selection | 3011 | `subnet_selection()`: `Ipv4Addr` | |
| 119 | Domain search | 3397 | `domain_search()`: `DomainSearch` | `domain_search` |
| 121 | Classless static routes | 3442 | `classless_routes()`: `Routes` | `classless_routes` |
| 124 | Vendor-identifying vendor class | 3925, 3 | `vendor_classes()`: `VendorClasses` | |
| 125 | Vendor-identifying vendor-specific information | 3925, 4 | `vendor_infos()`: `VendorInfos` | |
| 249 | Classless static routes (Microsoft's code) | 3442 format | `ms_classless_routes()`: `Routes` | `option` with `encode_classless_routes` |

Any other option is read with `Message::option(code)` and written with `MessageBuilder::option(code, value)`.

Notes on the types:

- **Message type.** `MessageType` names the eight types of RFC 2131 (DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM); every other value, among them FORCERENEW (RFC 3203) and the leasequery types of RFC 4388 and RFC 6926, is `Other(value)`.
- **Client identifier.** `ClientId::as_bytes()` is the whole value, the key a reservation by client identifier compares. Type 0 is any identifier, types 1 to 254 a hardware type and address (`hardware()`), type 255 the RFC 4361 form with an IAID and a DHCPv6 DUID (`iaid_duid()`, with the DUID's type, enterprise number and link-layer address). Linux clients with systemd-networkd send the RFC 4361 form; Windows and dhclient send type 1 with the MAC.
- **Client FQDN.** `ClientFqdn` gives the flags S, O, E and N, the two deprecated RCODE octets and the name as a `WireName`: in the canonical wire encoding when E is set, else in the deprecated ASCII encoding (a trailing zero octet, which some clients send, is ignored). A name without the root label is a partial name the server completes; an empty name leaves the name to the server. The builder answers with both RCODEs 255 (RFC 4702, section 2.2) and in the encoding the flags give, so the server answers in the client's encoding by passing on E.
- **Names.** `WireName` holds a name of at most 255 octets inline in its uncompressed wire form; `Display` writes the dotted text without a trailing dot, escaping `.` and `\` inside a label and octets outside printable ASCII as `\DDD`. The domain search list is compressed (RFC 1035, section 4.1.4); a pointer must point before the name it is in, and every further pointer before the one followed last, so a loop is refused, not followed.
- **Relay agent information.** `RelayAgentInfo` reads the sub-options in order and by code: circuit ID (1), remote ID (2), link selection (5, RFC 3527), subscriber ID (6, RFC 3993), server identifier override (11, RFC 5107) and relay agent identifier (12, RFC 6925). A link selection or server identifier override that is not four octets is a malformed option. `as_bytes()` is the value the server echoes.
- **User class.** RFC 3004 defines a list of length-prefixed classes; Windows and iPXE send one plain string. `UserClass::as_bytes()` is the value as sent and `classes()` the RFC form when the value follows it, so class matching can use either.
- **Classless static routes.** A route is a prefix length, the significant octets of the destination and the router (RFC 3442, section 3). The reader clears the destination bits after the prefix length, as the writer does; a prefix length above 32 is a malformed option.

### 1.5 The builder and its size rules

`MessageBuilder::reply(buf, &request, kind)` starts a reply: `op` BOOTREPLY, `htype`, `hlen`, `xid`, `flags`, `giaddr` and `chaddr` copied from the request, `hops` and `secs` zero, option 53 written first. The server sets `ciaddr`, `yiaddr` and `siaddr` as RFC 2131, table 3, asks for the message type, then appends options with the typed setters or `option(code, value)`, and `finish()` writes the end option and returns the length. `MessageBuilder::new(buf, limit)` builds any message, a request included.

- **The limit.** A reply stays within `Message::max_reply_len()` of the request: option 57 less the 28 octets of the IP and UDP headers when the option is at least 576, else 548 octets (576 less the headers, RFC 2131, section 4.1). A shorter buffer is a tighter bound; the server passes one to stay below its interface MTU. One octet is kept for the end option.
- **Nothing is truncated.** An option that does not fit returns `EncodeError::NoRoom` and leaves the message as it was before the call, a split option included; the server decides whether to answer without it.
- **Splitting.** A value longer than 255 octets is written as instances of 255 octets and a last shorter one (RFC 3396), each in the same area as the part before it or a later one. A value of 255 octets or less is never split, so clients without RFC 3396 support read it as they expect.
- **Overload.** After `allow_overload()`, three more octets of the options field are kept for option 52, and an option that does not fit into the options field goes into `file` (127 octets of options and its own end option) and then `sname` (63 and an end option). Each option goes into the first area with room, so a short option can still land in the options field after a long one went to `file`. A field the server set (`file` with a boot file name, `sname` with a server name) is not used for options, and setting a field that carries options already is `EncodeError::FieldInUse`. `finish()` writes option 52 with the areas used.
- **Padding.** `pad_to(300)` pads the finished message with zeros to the 300 octets that BOOTP relays and clients expect (RFC 1542, section 2.1); the padding counts against the limit.
- **Option 82.** `relay_agent_info` copies the request's option unchanged; the server writes it last (RFC 3046, section 2.2).
- **Longer values.** The typed setters for lists assemble the value on the stack, up to 2,048 octets; a longer domain search list or route list is encoded with `encode_domain_search` or `encode_classless_routes` into a buffer of the caller and written with `option`.

### 1.6 Errors and malformed messages

`DecodeError` names what went wrong: `TooShort` and `NoCookie` from `parse`; `Truncated` (an option's length octet or value runs past the end of its area, with the area); `BadLength` and `BadValue` (an option whose length or content its type does not allow, option 52 with a value other than 1 to 3 among them); `Split` (several instances, see section 1.3); `BufferTooSmall` (the caller's buffer for a joined option); `Hardware` (`hlen` above 16, or not Ethernet for `mac()`). No input makes the codec panic.

A malformed option ends the walk at that option and nowhere else:

- `options()` yields the options before it, then the error once, then nothing.
- An accessor returns the option it looks for when the option comes before the malformed one, and the error when it does not: the option may lie behind it.
- `validate()` walks every option and returns the first error.

The server decides. A request whose message type, client identifier and requested address are readable can be served even when an option after them is broken, which is what many servers do with buggy clients; a server that wants to refuse such messages calls `validate()` first. A malformed typed value (a bad client FQDN, say) is an error of that accessor only.

### 1.7 Tests and the fuzz target

The fixtures in `crates/tenko-dhcp/fixtures/` are annotated hex, one line per field or option, written independently of the builder: a DHCPDISCOVER of a Windows client, a DHCPDISCOVER of a Linux client with a DUID, a relayed DHCPREQUEST with option 82, a DHCPINFORM, a UEFI PXE DHCPDISCOVER, the RFC 3397 example of a split search list, and the malformed cases (a short message, no cookie, a truncated option, a bad option 52, a truncated option in `file`). Client messages are reconstructed by hand on documentation addresses and MACs. The tests:

- read every field and typed option of each fixture, and write every well-formed fixture again through the builder, octet for octet;
- build three replies with the typed setters and compare them octet for octet with their fixtures: the DHCPACK with a client FQDN, a compressed search list and option 82 echoed, a DHCPOFFER overloaded into `file` and `sname`, and a DHCPACK with a route list split over two instances;
- check the malformed cases with their exact errors and the options still readable before them;
- run loops over generated input (every truncation, octet flips, random option areas) that must not panic and must round-trip when they walk;
- count allocations (`tests/alloc.rs`): none in parsing, reading and building.

The fuzz target `dhcp_v4` (`fuzz/fuzz_targets/dhcp_v4.rs`, seeds in `fuzz/seeds/dhcp_v4/`, the fixtures as binary) parses arbitrary octets, walks every option, joins split ones, calls every typed accessor, decodes and encodes again the search list and the routes, and builds an OFFER for every message that parses, which must read back with option 53 first and within the limit.

## 2. The model

There is one register of networks and hosts, IPAM's (decision P3-Q4). DHCP adds rows to it in the `dhcp` namespace of the replicated store and never copies what IPAM holds:

| Object | Table | Keyed by | What it adds |
|---|---|---|---|
| Server settings | `dhcp.settings` | one row | lease times of scopes that set none, authority, the DDNS settings new scopes start from, conflict detection, the lease history retention |
| Scope | `dhcp.scopes` | the IPAM prefix | enabled, lease times, authority, server identifier, DDNS, shared network, restricted, admitted classes |
| Shared network | `dhcp.shared_networks` | its id | a name and an optional listener interface |
| Pool settings | `dhcp.pools` | the IPAM range | admitted classes and lease times |
| Exclusion | `dhcp.exclusions` | scope and id | an explicit range of addresses never leased |
| Option definition | `dhcp.option_defs` | its id | a custom code with a name and a type |
| Option set | `dhcp.option_sets` | its owner | the options of one level |
| Class, policy, filter | `dhcp.classes`, `dhcp.policies`, `dhcp.filters` | their ids | matches on requests, rules, MAC allow and deny entries |

A pool is an IPAM range of role `dhcp_pool`; a reservation is an IPAM host of mode `reserved` with an interface that has a MAC address or a client identifier and an address in a served network. Neither has a DHCP table of its own: the role derives them from IPAM's rows.

Every change is planned against a read view, checked with the rules of the model and committed as one inline job `dhcp.edit` (step `dhcp.write`) together with its audit record (`dhcp.scope.create`, `dhcp.option.set`, ...). The batch expects the versions it read, so a concurrent change makes it stale and the service plans again. A read of one object carries its store revision as the `ETag`; a change or deletion with `If-Match` is refused with 412 when the object has moved on. Deleting an owner deletes its option set in the same batch.

The `dhcp` role serves from a configuration image built from these rows and IPAM's, never from the store (`tenko_dhcp::config::image::build`). The build:

- takes every enabled scope whose prefix is a live IPv4 network; its lease times are its own, else the server's; it is authoritative as it says, else as the server says;
- takes the prefix's live ranges of role `dhcp_pool` as pools, each with the lease times of its settings, else the range's `lease_secs` as one fixed time, else the scope's;
- excludes the scope's exclusion ranges, the prefix's `reserved` and `infrastructure` ranges and every live address of the prefix that does not belong to a host of mode `dynamic` (a static server inside a pool is never offered);
- merges the options of the server, the scope's shared network and the scope, the later level winning per code;
- derives a reservation for every live address of status `active` or `planned` of every interface of every live `reserved` host in a served scope, keyed by the client identifier when the interface has one, else by its MAC address, with the interface's option set. An interface with neither gives the IPAM-18 warning `no_identity` and no reservation; when two hosts reserve one address or one client in a scope, the first (by host, interface and address id) wins and the warning names both (IPAM-23).

The build is checked against a reference that puts the same image together the slow way (marking each address of a network, merging levels code by code) over 512 random configurations per run with supernets, deleted rows, disabled scopes, IPv6 prefixes, ranges of every role, hosts of every mode, interfaces without identity and colliding reservations (`config/image_tests.rs`).

## 3. Scopes and pools

A scope serves exactly one IPAM prefix of role network and is keyed by it; `POST /dhcp/scopes` names the prefix. A supernet is refused (`dhcp.scope.not_network`), a prefix that has a scope already too (`dhcp.scope.exists`). The scope's batch expects the prefix's version, and IPAM, on its side, refuses to delete a prefix a scope serves or to turn it into a supernet (`dhcp.scope.attached`, 409; the rule of reverse zones). Delete the scope first; that deletes its exclusions, the settings and options of its pools, its policies with their options and its own options, and leaves the prefix and its ranges alone.

| Setting | Default | Notes |
|---|---|---|
| `enabled` | true | a disabled scope stays in the store and is not served |
| `lease` | the server's | `default_secs`, `min_secs`, `max_secs`, optional `t1_secs` and `t2_secs` (half and seven eighths when absent); `0 < min <= default <= max <= one year`, `t1 < t2 < default` |
| `authoritative` | the server's (true) | NAK for addresses of other networks |
| `server_id` | the listener's address | of the prefix's family |
| `ddns` | the server's DDNS settings | ADR 0020; the DDNS path is WP8.3's |
| `shared_network` | none | the nil UUID in a `PATCH` leaves the shared network |
| `restricted` | false, true under Hardened | only clients an allow filter matches are served (TGL-17) |
| `classes` | none | only clients of these classes are served |

Pools are created, moved and deleted through the IPAM range routes with role `dhcp_pool`; IPAM keeps them inside the network and away from each other and from reserved hosts. `PUT /dhcp/pools/{range}` sets what DHCP adds (classes, lease times) for a pool of a prefix with a scope (`dhcp.pool.not_pool` for another role, `dhcp.scope.not_found` without a scope); `DELETE` removes the settings and the pool's options, not the range.

Exclusions are explicit ranges inside the scope's network (`dhcp.exclusion.invalid` when unordered or outside). They may overlap; the image merges them.

`GET /dhcp/scopes/{prefix}/utilization` counts, over the pools: `pool_size`, the addresses a client can hold (the dynamic ones, neither excluded nor the network or broadcast address, and the reserved ones); `reserved`, the pool addresses of reservations; `leased` and `abandoned`, the dynamic addresses with an active (unexpired) or abandoned lease; `free`, what is left; and `utilization`, the used share. The scope list shows the pools and active leases of each scope, the pool list the size and active leases of each pool.

Shared networks group scopes on one link (Windows superscopes, Kea shared networks). A name is 1 to 64 characters of `a-z`, `0-9` and `-` and unique; a shared network that scopes name is not deleted (`dhcp.shared_network.in_use`). Shared networks are server-wide configuration.

## 4. Options and the catalog

`GET /dhcp/option-catalog` lists the built-in DHCPv4 options of RFC 2132 and its successors with Kea's names and their types, and the codes the server sets itself (`server_managed`: the requested address, lease and renewal times, overload, message type, server identifier, parameter list, message, maximum size, client identifier, client FQDN, relay agent information, client architecture and machine identifier, subnet selection), which no option set holds (`dhcp.option.code_reserved`).

A custom definition (`/dhcp/option-defs`) gives a code a name and a type: `ipv4_address`, `ipv6_address`, `ipv6_prefix`, `u8`, `u16`, `u32`, `i32`, `bool`, `string`, `fqdn`, `classless_routes`, `binary` or `empty`, with `array` for a list of a repeating type. In `dhcp4` a catalog code is refused; codes 224 to 254 are the site-specific range (RFC 3942). A vendor space (`space` other than `dhcp4` and `dhcp6`) holds the option 43 sub-options of its `vendor_class`. A space and code are defined once (`dhcp.option_def.exists`), a name once per space. The type of a definition an option set uses does not change, and a used definition is not deleted (`dhcp.option_def.in_use`).

Options are set per owner: `server`, `shared_network:<id>`, `scope:<prefix>`, `pool:<range>`, `policy:<id>` and `host:<interface>` (a reservation's options, on the IPAM interface). `PUT /dhcp/option-sets/{owner}` replaces the whole set; each value is given in wire form (`data`, hexadecimal) or typed (`typed`, for example `{"ipv4": {"values": ["192.0.2.53"]}}`, `{"text": "example.test"}`, `{"unsigned": [1500]}`, `{"names": ["example.test"]}`) and stored in wire form after it has been checked against the type of its code: `dhcp.option.unknown` for a code without a type, `dhcp.option.invalid` for data that does not fit or a code given twice. An `ipv6_prefix` value is a prefix length and the prefix's network address (the form of RFC 3633's prefix option): a prefix with a bit set beyond its length is refused, in wire form and typed alike, rather than cut, so that every value reads back as it was given. A `classless_routes` value reads with the destination bits after each route's width cleared, as RFC 3442's reader and the encoding clear them. An owner without options reads as an empty set at revision 0. Every value reads back with its name and its typed view.

The options a client gets merge the levels from the least to the most specific, the later level winning per code in the order the codes first appear: the server, the scope's shared network, the scope, the policies that match the client (the first in order wins per code), and the client's reservation. `GET /dhcp/scopes/{prefix}/effective-options?mac=&client_id=&vendor_class=&user_class=&architecture=&host_name=` (the client's MAC, option 61 in hexadecimal, options 60, 77, 93 and 12) shows the result, each option with its level and owner, and the reservation the client has. Pool options depend on the address the allocator picks and are shown on the pool. Which classes and policies match a client is the compiled matcher the engine uses (section 16), so the route shows the classes and policies the client is in and the options they give it.

## 5. Classes and policies

A class (`/dhcp/classes`) is a named match on the request that holds when any of its matches holds: vendor class (option 60, exact or prefix), user class (option 77), MAC address with wildcards, client identifier, relay agent circuit-id and remote-id, client architecture (option 93) and host name (exact or prefix). A name is unique; a class needs 1 to 64 matches. A class a scope, a pool or a policy names is not deleted (`dhcp.class.in_use`, parameter `by` with `scope:<prefix>`, `pool:<range>` and `policy:<id>`).

A policy (`/dhcp/policies`) belongs to a scope or, without one, to the server, where it applies after the scope's own. Its condition joins 1 to 64 terms with `and` or `or`: a class, a class negated, a match, a match negated (P3-Q12, the shape of Windows DHCP policies). Its action restricts the clients to an address range inside the scope's network (`dhcp.pool.outside` otherwise), sets lease times and DDNS settings; its options are the option set of `policy:<id>`. The name is unique in the scope; without `order` a new policy goes after the last of its scope. Policies apply in order, the first matching policy per action winning. How requests are matched, what each action does and how the class lists of scopes and pools admit clients is section 16.

## 6. MAC filters

A filter entry (`/dhcp/filters`) allows or denies a MAC pattern server-wide (DHCP-08): six octets in hexadecimal separated by `:` or `-`, any of them `*`, or a prefix ending in `*` (`00:00:5e:00:53:*`), stored lowercase with colons. A pattern has one entry (`dhcp.filter.exists`). A deny entry drops the client on every scope; on a scope marked restricted only clients an allow entry matches are served, and deny wins over allow.

## 7. The API and the command line

The routes are under `/api/v1/dhcp` and belong to the DHCP module (OPS-25): a server without it registers none of them (404 `sys.route_not_found`). The scopes are `dhcp.read` and `dhcp.write`; a scope is the object `dhcp_scope` with its prefix's identifier, so a scoped grant on the prefix reaches it (IAM-01), and lists show only the scopes, pools and option sets the caller may read. A pool and a pool's options are checked on the pool's scope. Settings, shared networks and the server's options are server-wide, on the `dhcp_scope` singleton, which only global roles reach; classes, policies, option definitions and filters are global-only kinds. Lists are pages with a cursor (`limit` up to 1,000).

| Route | What |
|---|---|
| `GET`, `PUT /dhcp/settings` | the settings, with `effective_conflict_detection` and `effective_history_days` from the security profile for the values left to it (TGL-16: on except under Lab; P3-Q13: 30 days under Home, 90 under Standard and Hardened, 7 under Lab) |
| `GET`, `POST /dhcp/scopes`; `GET`, `PATCH`, `DELETE /dhcp/scopes/{prefix}` | scopes |
| `GET /dhcp/scopes/{prefix}/utilization`, `GET /dhcp/scopes/{prefix}/effective-options` | how full a scope is; a client's options |
| `GET`, `POST /dhcp/scopes/{prefix}/exclusions`; `DELETE /dhcp/scopes/{prefix}/exclusions/{id}` | exclusions |
| `GET`, `POST /dhcp/shared-networks`; `GET`, `PATCH`, `DELETE /dhcp/shared-networks/{id}` | shared networks |
| `GET /dhcp/pools`; `GET`, `PUT`, `DELETE /dhcp/pools/{range}` | pools and their settings |
| `GET /dhcp/option-catalog`; `/dhcp/option-defs`; `/dhcp/option-sets/{owner}` | the catalog of both spaces (`space=dhcp4` or `dhcp6` keeps one), definitions, option sets |
| `/dhcp/classes`, `/dhcp/policies`, `/dhcp/filters` | classes, policies, filters |

The reservation, lease, history and export routes and the node routes answer 501 `sys.not_implemented` until their packages (WP8.1, WP7.2, WP7.5, WP9.3). The error codes are those of [dhcp-contracts.md](dhcp-contracts.md) section 6. When the server runs no configuration service the configuration routes answer 409 `dhcp.module.disabled`.

The command line has a command per object, each checking what it can without the server before it sends (a mistake is a usage error, status 2) and printing the API's problems with their code (status 5):

```
tenko dhcp settings show | set [--lease-default S --lease-min S --lease-max S] [--authoritative BOOL] [--history-days N] [--conflict-detection BOOL]
tenko dhcp scope list | show PREFIX | create PREFIX [...] | set PREFIX [...] | delete PREFIX | utilization PREFIX | options PREFIX [--mac MAC] [--client-id HEX]
tenko dhcp exclusion list PREFIX | add PREFIX FIRST LAST | delete PREFIX ID
tenko dhcp shared-network list | show ID | create NAME | set ID | delete ID
tenko dhcp pool list [--scope PREFIX] | show RANGE | set RANGE [--class ID] [--lease-...] | clear RANGE
tenko dhcp option catalog | defs | define --code N --name NAME --kind KIND [--array] [--space S] | undefine ID | show OWNER | set OWNER CODE=HEXDATA... | clear OWNER
tenko dhcp class list | show ID | create NAME --match JSON... | set ID [--name NAME] [--match JSON...] [--description TEXT] | delete ID
tenko dhcp policy list | show ID | create --file POLICY.json | set ID [--file CHANGE.json] [--name NAME] [--order N] [--enabled BOOL] [--description TEXT] | delete ID
tenko dhcp filter list | add MAC-PATTERN --allow|--deny [--note TEXT] | delete ID
```

Every command takes `--json` for the API's answer as is. `crates/tenko/tests/acceptance_dhcp_config.rs` runs the configuration through the real binary: a scope, an exclusion, a pool's lease times, options from `CODE=HEXDATA` at two levels, a custom definition, a class, a filter and the settings, the effective options of a client, and the prefix that IPAM keeps while the scope exists.

The web UI's DHCP area (`/dhcp`) has the scope list with utilization, the scope page with its pools, exclusions, options and effective options, the shared networks, the options with the catalog and the custom definitions, the classes and policies, the MAC filters, and the DHCP section of the settings (`/settings/dhcp`). WP8.6 completes it: the scope page's DDNS tab (every field of the scope's DDNS settings, the server's settings it starts from and what the security profile does; a scope's own settings cannot be cleared back to the server's through the API, so the tab offers to copy the server's) and network boot tab (the boot server and file options 66, 67, 150 and 209 to 211, the scope's boot policies per client type and a dialog that adds one as a class, a policy and its option 67); the policy editor's four actions (options, range, lease time, DDNS) and an architecture picker for option 93 matches; the effective view that takes a client's MAC, client identifier, vendor class, user class, architecture and host name and says, per option, which level and which policy gave it; the lease list's live strip (the chosen scope's utilization, or a bar per scope, and the leases granted since the page was opened); the host page's DHCP reservations block (each address of a `reserved` host with the identity it is keyed by, the scope it falls in, whether the role serves it and its lease); the action Reserve in DHCP on the IPAM address page and in the row menus of the address list and of a network's addresses, and Reserve this address in the lease list's row menu (section 12.1): offered where the address's prefix has a scope (served or not, which the dialog says with a link to the scope) to a principal who may write IPAM there and DHCP, it opens a dialog with the address, the host (the address's, the host IPAM knows for the lease's client, or a new one named after the address's DNS name, the lease's host name or what discovery saw), the interface (one of the host's or a new one), the MAC address (prefilled from the interface, the lease on the address or the observations), an optional client identifier (prefilled from the lease) and the status, says in sentences what the save changes ("Host printer-1 becomes reserved (it is static now)", "Interface eth0 gets the MAC address ...", "The address 192.0.2.30 stays active", what the reservation is keyed by, whether the scope serves it), refuses an address inside a DHCP pool and offers, from a lease, the next free address outside the pools instead, saves with one request, and then shows the reservation as the host page's block does with links to the scope and the host; the address page of a `reserved` host shows that block too, and a lease that is its client's reservation says Reserved with a link to the host and offers to open it instead; and the first-run wizard's DHCP step (the first scope and the listener, written after setup, with the `[dhcp]` section on the result step).

WP9.4 adds DHCPv6 to the area (section 19.8). The scope list tags each scope DHCPv4 or DHCPv6 and the create dialog offers IPv6 networks. The page of a DHCPv6 scope has a DHCPv6 tab with the preferred lifetime (empty means five eighths of the valid lifetime, and the tab says the value that gives for the scope's lease time; a value above the valid lifetime is refused), Rapid Commit (on by default) and the relay Interface-Id, saved as the whole `v6` object, and Use the defaults, which sends `clear_v6`. The DHCPv4-only parts of the page are left out with a line saying why: the network boot tab, the server identifier, the admitted classes and the effective options view, which asks for DHCPv4 facts. The options tab edits the scope's `dhcp6` options with the DHCPv6 catalog, typed as the catalog says (an address list for 23, a domain list for 24), and the server's options page holds both spaces. A pool of 2^32 addresses or more is shown as a power of two. The lease list and the history page have a family filter and a DUID filter in the URL, a family column, the kind of a lease (an address, or a delegated prefix shown as `prefix/length`), the client's MAC address where it is known and the DUID and IAID of a DHCPv6 client, and a lease whose client has a lease of the other family with the same MAC address links to it. The node strip counts the listeners, scopes and active leases of both families. The host page's reservations block lists the IPv6 addresses of a reserved host beside the IPv4 ones, keyed by the interface's DUID, else its MAC address, with the lease on the address and a warning when another client holds it. Reserve this address in the lease list's row menu stays DHCPv4 only; a DHCPv6 reservation is made on the host. The start page's DHCP tiles count both families: the active leases, the grants per second (DHCPv6 REQUESTs, RENEWs and REBINDs answered beside the DHCPv4 REQUESTs) and the fullest scopes.

The second half of WP9.4 adds prefix delegation (sections 19.10 to 19.12). The IPAM range form offers the role Delegation pool on an IPv6 network only, with a delegated length that the form checks as IPAM does (longer than the network's length, at most 64, the first and last address on that length's boundaries) and the server's `ipam.validation` errors on the length and the role; a network's ranges show a delegation pool's length and its size in prefixes. The pools tab of a DHCPv6 scope lists the address pools and, in a section of their own, the delegation pools with their range, delegated length, prefixes, bound prefixes and lease time, and adds one through its own dialog (an IPAM range of role `dhcp_pd_pool`); the settings tab gives the delegated prefixes bound beside the address figures. In the lease list a delegated prefix is `prefix/length` with Holds Prefix, the filter Holds (`kind=na|pd` in the URL) keeps addresses or prefixes, the address filter takes an IPv6 prefix and finds the leases inside it and the delegated prefixes that hold an address, and a delegated prefix links to the address lease of the same router (Router address); the history shows a prefix the same way. The leases page's node strip gives the server DUID and a panel of the router advertisement check: whether it runs, the links heard with their routers, the M and O flags, the advertised prefixes and the scopes, and each finding in words; the Nodes page shows the `dhcp.ra.*` health rows in the same words.

## 8. Leases

A lease is a row of `dhcp.leases` in the replicated store, committed before the ACK (decision P3-Q1, [ADR 0019](adr/0019-dhcp-data-model-and-lease-path.md)); there is no lease file. The `dhcp` role serves from a lease table in memory that equals the rows, and never reads the store while it answers. The code is `tenko_dhcp::lease` (WP7.2); the contracts it implements are in [dhcp-contracts.md](dhcp-contracts.md), section 3.

### 8.1 The lease change

The engine builds a lease change (`PendingChange`: every field inline, no heap) for a REQUEST, a renewal, a rebind, a release or a decline, and hands it to the lease store (`StoreLeases::submit`). The hand-off copies the change into a queue sized at start (4,096 changes) and returns at once; it never allocates and never waits for the disk (`tests/lease_alloc.rs`). A full queue drops the request (`tenko_dhcp_dropped_total{reason="queue"}`); the client retries. A DISCOVER writes nothing: the offered address is held in memory for the offer lifetime (`[dhcp] offer_secs`, 10 s) in the offer hold (`OfferTable`), which has room for a fixed number of offers and allocates nothing either.

The committer, a task of the role, turns each change into one store batch with one revision:

| Table | Key | What the batch writes |
|---|---|---|
| `dhcp.leases` | VRF, address | The row after the change; fields the change does not carry (DDNS state, partner times, observation time) come from the row held before, for the same client |
| `dhcp.leases.by_client` | scope, client identity | The client's latest row in the scope; when the address was another client's, that client's entry moves to its next row or is removed |
| `dhcp.history` | time, VRF, address | The event (`granted`, `renewed`, `rebound`, `released`, `declined`, `reclaimed`) |
| IPAM observations | | The fact of `dhcp:<node>`, through the observation hook that WP8.1 fills; nothing until then |

The batch is written as the system component `dhcp`; lease commits are not audited one by one, the history is their record. A change that would take an address another client still holds (an unexpired binding or an abandoned address) is refused before it reaches the store: it is the last guard of "no address on two clients", behind the allocator and the offer hold. An operator's reclaim may take it.

Batches are proposed concurrently, up to 512 at a time, so that the store's coalescer folds what waits into one Raft entry and one fsync. Two changes that touch the same address, or the same client as new or as previous holder, are proposed one after another, each built from the table after the one before has applied, so the rows and the index never depend on the order in which commits finish.

### 8.2 When the ACK leaves

The ticket of a change completes, and the worker sends the ACK, only after the store has answered the batch (on one node: its log entry is on disk and applied) and the committer has applied the row to the role's table at the commit's revision. A change that has not committed within 2 seconds of its hand-off completes as failed and the request is dropped, as the DNS update path answers SERVFAIL when its index wait passes ([dns.md](dns.md)); a commit that lands later still reaches the table, and the client's retry finds its lease. The time from the hand-off to the completion is `tenko_dhcp_commit_duration_seconds`.

### 8.3 The table

The table (`LeaseIndex`) holds every row by VRF and address and, per scope, by client identity, with each client's rows beside its index entry. It takes rows from two sides: the committer's own commits at once, and the feed's copy of every row (`DhcpFeed`: an image at a revision, then the deltas in revision order, a new image after a snapshot install). A row replaces the one held unless the held one is newer: written at a later revision when both revisions are known, else with a later client transaction time. So the feed's copy of an own commit changes nothing, an older copy never overwrites a newer row, and a new image keeps the rows of commits after its revision until the deltas bring them. A delta that does not follow the revision held is a gap, and the role reads a new image.

At start the table is rebuilt from the store, page by page (`rebuild_from_view`). The measured figures are in `bench/phase3-dhcp/results/` (E24, M32): a table of 100,000 leases rebuilds well within the 5 seconds the plan sets.

### 8.4 Expiry

Expiry is a leader service (`dhcp.expiry`, every 10 s). It finds the rows whose state has ended (an active binding past its end, an abandoned address past its hold) and writes them as `expired`, with a history row each, in batches of 256 rows. Each batch carries the leader fence and a version precondition per row: a renewal committed in between makes the batch fail and the row is looked at again in the next round, and a controller that has lost the leadership writes nothing. The client index does not move. The same round drops ended offers from the offer hold. Expiry does not decide whether an address is free (the allocator already treats a binding past its end as free); it makes the row say so, records the event and lets DDNS remove the records (WP8.3). It counts `tenko_dhcp_expired_total`.

### 8.5 History retention

`dhcp.history` is bounded by a retention in days (P3-Q13): the node's `[dhcp.history] days` if set, else the replicated `history_days` of the DHCP settings, else the security profile's default.

| Profile | Days |
|---|---|
| Home | 30 |
| Standard | 90 |
| Hardened | By policy; 90 unless set, and every purge is in the audit export |
| Lab | 7 |

A leader service (`dhcp.history.purge`, hourly) deletes the rows older than the retention in batches of 1,000 under the leader fence, each batch with one audit record `dhcp.history.purge` that names the cut-off and the count. `tenko_dhcp_history_purged_total` counts the purged rows and `tenko_dhcp_history_rows` the rows held (counted once per term of office, then kept from the writes and the purges). Every lease change writes one row, renewals included: a network of 100,000 clients on one-hour leases writes about 55 rows a second, so at that size the retention is a setting to choose with care.

### 8.6 While the store refuses

On one node the store refuses a write only when its disk fails, or through the test hook `TENKO_TEST_REFUSE_WRITES_FILE`; in Phase 5 also when a node loses its quorum. The role then promises nothing it has not committed (P3-Q14):

- a renewal, a rebind or a request for the address a client holds is answered with an ACK for the time the lease has left: no extension, nothing written;
- every other request is dropped, and the client retries; it counts `tenko_dhcp_dropped_total{reason="store_refused"}`;
- every refused write counts `tenko_dhcp_store_refused_total`, and the health finding `dhcp.role.store_refused` is raised with the time of the first refusal and the counts since.

After a refusal the role tries the store again after one second: the next change goes to the store, a commit clears the finding, and another refusal waits another second. No probe write is made.

### 8.7 Tests and the crash test

The tests are in `crates/tenko-dhcp/tests/`: `lease_table.rs` (the table against the reference table on random sequences, the index moves, the feed, own commits against older copies), `lease_store.rs` (the batches against the reference lease store, a burst of concurrent changes, another client's binding, the queue, a slow commit, a refusing store), `lease_services.rs` (expiry, its fence and its race with a renewal, the offer hold, the retention and the purge), `lease_refusal.rs` (the refusal path on the Raft store with the hook, in a child process), `lease_alloc.rs` (no allocation on the hand-off, the lookups, the offer hold and the refusal gate), `lease_rebuild.rs` (the rebuild of a large table and the commit latency) and `lease_crash.rs`.

The crash test (E24, M32) kills a node under load and restarts it, again and again. The node is a child process of the test: it opens the Raft store, rebuilds its table and runs 200 clients that request, renew and release through the allocator, the offer hold and the lease store, and it prints a line for an ACK only after its ticket completed. The test kills it at a random moment (SIGKILL on Unix, TerminateProcess on Windows), opens the data directory and checks that every ACK received is in the rows at its revision or later, that its history row is there, that the rebuilt table equals the rows and the client index, and that the history never gives an address to a second client while the first one's binding had not ended. `bench/phase3-dhcp/scripts/crash-test.sh` runs it 20 times with the rebuild and the latency measurement; the results, and the procedure of the power-off runs on the lab VM, are in `bench/phase3-dhcp/results/`. Until the `dhcp` role exists in the binary (WP7.5), the crash test drives the lease path through this test entry point rather than through `tenko serve`.

## 9. The engine

The DHCPv4 engine (`tenko_dhcp::v4::engine`, WP7.3) is a pure function: `engine::handle` takes the configuration image, the lease table, the offers held, the request with the listener it arrived on, and the clock, and returns what to do, with the reply and the lease change written into the worker's buffers. It reads no store and does no I/O; the listeners and workers (`tenko_dhcp::server`) wrap it in sockets and the commit. From the parse of the request to the hand-off of the lease change to the `LeaseStore` it allocates nothing (`crates/tenko-dhcp/tests/alloc.rs` runs it over the fixtures and the request corpus and fails on one allocation).

### 9.1 The client and the scope

The client is its client identifier (option 61) when it sends one, else its hardware type and `chaddr` (RFC 4361, RFC 6842); its leases and offers are kept under that identity, and option 61 is echoed in every reply. A reservation is looked up by the client identity first and then by the hardware address (WP8.4): a reservation keyed by MAC holds for a client whose `chaddr` it names whether or not the client sends option 61 (Windows sends one of type 1 with the MAC, some Linux clients a DUID), a reservation keyed by a client identifier holds only for that identifier, and where a client has both kinds the client identifier's wins. Until WP8.4 a reservation was looked up by the client identity only, so a client that sent option 61 missed the reservation of its MAC. A MAC address the deny list matches is dropped (`filtered`, DHCP-08). A scope marked restricted serves only clients the allow list matches and clients with a reservation in it (TGL-17); everyone else is dropped as `filtered`.

The scope is selected by the first of: the link selection sub-option of option 82 (RFC 3527), option 118 (RFC 3011), `giaddr`, `ciaddr` of a REQUEST, INFORM or RELEASE that is not relayed (a renewal unicast straight to the server, which in relay mode is how every renewal arrives), and the address of the listener the request came in on. The most specific network that holds the address wins, and a scope of a shared network brings its siblings into the choice of address. The server identifier (option 54) is the relay's override (RFC 5107, sub-option 11), else the scope's, else the listener's address; a client's option 54 names this server when it is any of these.

### 9.2 The messages

| Request | State (RFC 2131 4.3.2) | Answer | Written |
|---|---|---|---|
| DISCOVER | | OFFER with the allocator's address; dropped as `pool_full` without one | Nothing; the address is held in memory for `offer_secs` (10 s) |
| REQUEST with option 54 and 50 | SELECTING | Option 54 of another server: ignored. The requested address, when the allocator gives it to this client: ACK after the commit. Otherwise NAK | The lease (`granted`, or `renewed` for the client's own bound lease) |
| REQUEST with option 50, no 54, no `ciaddr` | INIT-REBOOT | An address outside the network: NAK on an authoritative scope, else ignored. No reservation and no lease of the client: ignored (RFC 2131 says the server stays silent). The client's address: ACK after the commit; another address: NAK (authoritative) | The lease |
| REQUEST with `ciaddr`, not relayed | RENEWING | The client's address, or a free pool address it holds without a record (a lost lease is taken back): ACK to `ciaddr` after the commit. Another client's address: NAK (authoritative), else ignored | `renewed`, or `granted` |
| REQUEST with `ciaddr`, relayed | REBINDING | As RENEWING, to the relay | `rebound`, or `granted` |
| DECLINE | | The client's address: no reply. Another client's address or another server's: ignored | The address `abandoned` for `[dhcp.decline] hold_secs` (86,400) with no client, so that it is offered to nobody, the decliner included, until the hold ends |
| RELEASE | | The client's active lease: no reply. Otherwise ignored | The lease `released`, ending now |
| INFORM | | ACK with the options and no lease times, `yiaddr` 0, to `ciaddr` | Nothing |
| Any other type, a BOOTREPLY, BOOTP without option 53 | | Ignored | Nothing |

A NAK carries option 53, 54, a message (option 56), option 61 and option 82 and nothing else; through a relay it has the broadcast bit set so that the relay broadcasts it (RFC 2131 section 4.3.2). In SELECTING a NAK is sent on every scope, since the client chose this server; in the other states only on an authoritative scope.

While the store refuses lease writes (P3-Q14), a REQUEST for a bound lease of the client is answered with an ACK for the time the lease still has and nothing is written, a DISCOVER is answered only for a client with a bound lease, and everything else is dropped as `store_refused`; a commit that fails after the hand-off drops its ACK the same way.

### 9.3 Where replies go

RFC 2131 section 4.1: to the relay at `giaddr` on port 67 when the request was relayed; else a NAK is broadcast; else to `ciaddr` on port 68; else broadcast when the client set the broadcast flag; else to the client's hardware address with `yiaddr` as the destination. That last case needs a link-layer socket (`AF_PACKET` with `CAP_NET_RAW` on Linux), which the role adds in WP7.5; until then, and always on Windows, such a reply is broadcast on the listener's link, which every client accepts. The relay port and the client port are settings of the engine so that tests and benches can use others.

### 9.4 The allocator and the offers

The order is the plan's (section 2.3): the client's reservation, its bound lease, the address it asks for when that one is free, then a free pool address. The engine's allocator (`HashedAllocator`) walks a pool from a start that the hash of the client's identity gives and wraps at its end, instead of from the lowest address: two nodes of a Phase 5 pair do not reach for the same address, and a client whose lease ended finds its old address first when nobody took it. Free means in a pool, not excluded (the network and broadcast addresses always are), not reserved for another client, no other client's binding (active or abandoned), no other client's unexpired offer, and owned by this node (`PoolOwnership`, `SingleNode` on one node). The tests check it against the reference allocator over random scopes, leases, reservations and offers (`tests/engine_allocator.rs`).

The offers held (`OfferTable`) are a fixed table of stripes with a mutex each and a bounded probe, made when the role starts: holding and looking up an offer never allocates, and a full table forgets the offers that end first. A worker claims the address it offers, and a claim fails when another worker holds it for another client, so that one address is never offered to two clients at once; an ACK claims its address the same way while its commit is in flight. An offer is not withdrawn when the client chooses another server; it ends after `offer_secs`.

The lease time is `grant_time` of the times of the address's pool (else the scope's) for the time the client asks for in option 51, with T1 and T2 from the same times.

### 9.5 The options

The value of a code is the most specific level's: the reservation's (host), the first matching policy's that holds it (section 16), the pool's, then the scope's, which the image holds already merged with the shared network's and the server's. The reply carries option 53, 54 and the lease times first, then the subnet mask (configured, else the scope's prefix length; RFC 2132 wants it before the routers), then every option the client lists in option 55 in the client's order (a split option 55 is joined first), then the routers, the DNS servers and the domain name when they are set and were not asked for (as Kea sends them), then option 61, option 81 and option 82 unchanged and last (RFC 3046). Codes the server manages (`SERVER_MANAGED_V4`) never come from an option set. Room for the closing options is kept; an option that does not fit within the client's size (option 57, else 548 octets) is left out whole. A value above 255 octets goes out as consecutive instances (RFC 3396). Overload into `file` and `sname` stays off until the scope has a switch for it. A boot client with a boot file gets the boot options and the `file` and `siaddr` fields of section 16.2.

Option 81 is answered as a server that performs no DNS update (RFC 4702 section 4): N set, S clear, O set when the client asked for S, E as the client sent it, the client's name echoed. DDNS (WP8.3) changes the flags when it writes the records.

### 9.6 The listeners and workers

`DhcpServer::start` binds every `[dhcp] listen` entry through `socket2`, the safe socket API of the DNS role, and starts the workers of ADR 0009: one `SO_REUSEPORT` socket per worker on Linux, one shared socket on Windows. `socket2` 0.6 has no safe way to ask for `IP_PKTINFO`, so the receiving interface and address come from the binding instead:

| Mode | Linux | Windows |
|---|---|---|
| `relay` | Binds the unicast address on port 67; only relayed and unicast traffic arrives. Needs `CAP_NET_BIND_SERVICE` only | The same |
| `direct` | Binds `0.0.0.0` on port 67 with `SO_BINDTODEVICE` to the entry's interface and `SO_REUSEADDR`, so that each interface has its socket and its broadcasts; without an interface name one socket hears every link. Replies to a hardware address go out through the link-layer socket of the interface (section 10.3), else as broadcasts | Binds the interface's address, on which Windows delivers that interface's broadcasts; replies to a hardware address are always broadcast |

A worker runs the engine and sends an OFFER, a NAK or an INFORM's ACK at once. For an ACK it copies the lease change and the reply into a slot of a fixed table under a ticket and hands the change to the `LeaseStore`; it never waits for the disk. The committer thread takes the store's completions: a committed change is applied to the lease table at once (the feed's copy of the row changes nothing later, `LeaseTable::apply`) and its ACK is sent; a refused one is dropped and counted. A full slot table or store queue drops the request as `queue`.

The counters are per worker, relaxed atomics: `tenko_dhcp_packets_total` by type and outcome, `tenko_dhcp_dropped_total` by reason, the NAKs, the DECLINEs, the refused commits, and the histograms of DISCOVER to OFFER, REQUEST to ACK and the commit; `DhcpServer::metrics` sums them, and the role registers them (section 10.6).

### 9.7 Tests and measurements

- `tests/engine.rs`: a table of RFC 2131 cases (every message type and REQUEST state, the NAK rules, the server identifier, the broadcast flag, every destination) and the cases around it (lease times and the commit, DECLINE's hold, RELEASE, the NAK's options, the order of option 55 and the split routes, reservation options, option 81, link selection with the server identifier override and option 118, the store refusal, restricted scopes, a full pool).
- `tests/engine_corpus.rs`: the corpus `fixtures/requests/*.hex` (requests of Windows, ISC dhclient, systemd-networkd, Android, macOS and PXE firmware modelled by hand on the option order and the parameter request lists these clients send, relays with option 82, renewals, INIT-REBOOT, DECLINE, RELEASE, INFORM; documentation addresses and MACs) answered octet for octet as recorded in `fixtures/requests/expected/`, every reply decoded by `dhcproto` and checked for option 53 first, option 61 and option 82 echoed, option 82 last, the size limit and the order of option 55. `TENKO_BLESS=1` rewrites the recorded answers after a deliberate change. WP7.6 adds requests captured in the lab.
- `tests/engine_allocator.rs` and `tests/engine_server.rs`: the allocator against the reference, and a relay listener on loopback running DORA, a renewal, a release and a refused commit through `MemLeaseStore`.
- `crates/tenko-dhcp/examples/dhcp_server.rs` serves the engine on a port for perfdhcp and carries a load client; `bench/phase3-dhcp` runs M26 to M28 with it on loopback.

What the engine left to later packages came with them: the conflict probe before an offer and the DECLINE rules (section 14, WP8.5), DDNS (section 13, WP8.3), and the classes, policies, class restrictions and boot options (section 16, WP8.4).

## 10. The role

The `dhcp` role runs in the controller's process, as the `dns` role does (ADR 0004, plan sections 2.10 and 2.12): `roles = "controller,dhcp"` (or `controller,dns,dhcp`) in `tenko.toml` or `--roles`, with the DHCP module on. A role list without the controller is refused with status 2 until Phase 5 brings nodes of their own. `crates/tenko-dhcp/src/role.rs` is the role; `crates/tenko/src/serve/dhcp.rs` is its start step.

### 10.1 The start order

The step `dhcp` is the fifteenth of `tenko serve`, after the API and the `dns` role, before the leader services start:

1. The role's metric families join the process registry (section 10.6).
2. The in-process feed registers with the store (`tenko_dhcp::store_feed`, the derived index `dhcp.serving` over the tables of `NODE_TABLES` and `NODE_IPAM_TABLES`) and gives the first image of the rows: the configuration, the leases and the IPAM prefixes, ranges, hosts, interfaces and addresses.
3. The configuration image (section 3) and the lease table (`LeaseIndex` in a `SharedLeases`, section 8) are built from that image.
4. The lease store on the replicated store (`StoreLeases`) and its committer start, with the refusal gate of P3-Q14 in front of it.
5. The listeners of `[dhcp] listen` bind and the workers start over the image and the shared table. Only now does the node answer, from complete tables; the ready line says `dhcp role answering on <address>:<port> (<mode>), <n> scope(s) at revision <r>, <m> lease row(s)`.
6. The leader services `dhcp.expiry` (over the role's table) and `dhcp.history.purge` (the retention of P3-Q13 with `[dhcp.history] days`) are registered; a follower keeps the retention's profile and the probe expectation current when the security profile changes.

While it runs, the follower takes the feed's events. A delta's lease rows go into the table at the delta's revision: the role's own commits are there already (the committer applies a row before the ACK leaves), so the copy changes nothing, and an older copy never overwrites a newer row. A delta's configuration rows go into the kept rows, from which the image is rebuilt and swapped whole. After a snapshot install the store builds the index aside and hands the feed a new image: the role builds the image and the table from it aside, carries over the rows it committed after the image's revision, and swaps both under the table's write guard (`DhcpServer::swap`). A worker takes the table's read guard before it looks at the image, so no request is answered from a new image and an old table or the reverse. A feed that fails is read again whole after a second; the role keeps serving the rows it holds meanwhile (OPS-02).

The role stops first when the process stops, with the `dns` role: the listeners close and the workers end, then the follower and the committer, whose queued changes are failed so that no ACK leaves for them; then the leader services and the store. A change of the module set stops the process with status 12 for a restart, as for every role.

### 10.2 Configuration

The node-local keys (`docs/dhcp-contracts.md` section 9, `deploy/tenko.example.toml`):

| Key | Default | Meaning |
|---|---|---|
| `[dhcp] listen` | none | Listeners: `{ address, mode = "relay" or "direct", interface }`, or an address alone for relay mode; an IPv6 address is a DHCPv6 listener on `[dhcp.v6] port` (section 19.7). Empty: the role builds its tables and answers nothing (the health row `dhcp.role.not_serving`) |
| `[dhcp] port` | 67 | The server port |
| `[dhcp] workers` | one per CPU, at most 8 | UDP workers per listener, 0 to 64 |
| `[dhcp] offer_secs` | 10 | How long an offer holds its address in memory, 1 to 300 |
| `[dhcp] relay_port`, `client_port` | 67, 68 | Where replies to relay agents and to clients go (tests and labs use other ports) |
| `[dhcp] proxy`, `proxy_port` | none, 4011 | Proxy DHCP listeners for boot clients (WP8.4, section 16.3): unicast IPv4 addresses, each listed once, not on `port` where `listen` holds the same address |
| `[dhcp.probe] timeout_ms`, `cache_secs` | 300, 600 | The conflict probe (WP8.5) |
| `[dhcp.decline] hold_secs` | 86,400 | How long a declined address stays abandoned |
| `[dhcp.ddns] retries`, `backoff_ms` | 5, 1,000 | The DDNS worker (WP8.3) |
| `[dhcp.history] days` | the installation's setting, else the profile's | A node-local retention of the lease history, 1 to 3,650 days |

`tenko config check` refuses an entry that is not a unicast address, an interface on a relay listener, an address listed twice, and values outside the ranges above.

### 10.3 The listeners per platform and mode

| | Relay mode | Direct mode |
|---|---|---|
| Linux | Binds the unicast address on port 67; only relayed and unicast traffic arrives. One `SO_REUSEPORT` socket per worker | Binds `0.0.0.0:67` with `SO_BINDTODEVICE` to the interface, one socket that the workers share: Linux hands a broadcast to every socket of a `SO_REUSEPORT` group, so a socket per worker would answer each broadcast once per worker. A reply to a client without an address that did not ask for a broadcast goes to its hardware address through an `AF_PACKET` socket of the interface (`pnet_datalink`, the scanner's safe link-layer API; Ethernet, IPv4 and UDP headers framed by the role, UDP checksum zero); without `CAP_NET_RAW`, or without an interface name, it goes out as a broadcast |
| Windows | Binds the unicast address; one socket shared by the workers | Binds the interface's address, on which Windows delivers that interface's broadcasts; replies to a hardware address are broadcast |

The receiving address comes from the binding, not from `IP_PKTINFO`: `socket2` 0.6 has no safe way to ask for that control message, and every binding above names its interface or address, so none needs it; the configuration check refuses a wildcard listener for that reason. The reference topology (P3-Q5, E23) runs relay mode only: the gateway relays every network, the node's own included, to the node's address, so the node never answers a broadcast and a request never arrives twice (R56).

### 10.4 Capabilities and deployment

| Platform | Relay mode | Direct mode |
|---|---|---|
| systemd (`deploy/systemd/tenko.service`) | Nothing new: port 67 is covered by the unit's `CAP_NET_BIND_SERVICE` | The drop-in `deploy/systemd/dhcp-direct.conf`: `CAP_NET_RAW` (`SO_BINDTODEVICE` and the link-layer socket) and the address families `AF_NETLINK` (the interface list) and `AF_PACKET` |
| Unprivileged LXC | Works: the container's root may bind port 67 | Needs `CAP_NET_RAW` and `AF_PACKET` in the container, which an unprivileged container usually withholds; use relay mode |
| Containers | A published UDP port (`-p 67:67/udp`); the gateway relays to the host's address | `network_mode: host` or macvlan, with `CAP_NET_RAW` |
| Windows (MSI) | The firewall rule for UDP 67 is added when `TENKO_ROLES` holds `dhcp` (or `all`) | The same rule; broadcast replies |

UDP 547 (DHCPv6, section 19.7) needs nothing more in relay mode. The installer (`deploy/install.sh`) offers `controller,dhcp` and `controller,dns,dhcp`, checks that no other process holds UDP 67, and reminds that `[dhcp] listen` must be set. `deploy/README.md` has the walk-through.

### 10.5 The status route and the node commands

`GET /nodes/{id}/dhcp` is the role's report `dhcp.status`: whether it answers (`serving`: it runs and has a listener of `[dhcp] listen`), whether the store takes its lease writes (`accepting`, P3-Q14), whether a probe role runs (`probe`), the listeners with their address, port, mode, interface and workers (the table below), the scopes the image serves, the leases by binding state, the last commit's time from the hand-off to the durable commit (`last_commit_ms`) and the revision of the image. The report also carries, for the health view, the refusal finding, the probe expectation, the lag behind the store and the number of images installed since the start.

| `mode` | Listener | Port | Workers |
|---|---|---|---|
| `relay` | `[dhcp] listen` in relay mode: the unicast address, relayed traffic only | `[dhcp] port` (67) | `[dhcp] workers` |
| `direct` | `[dhcp] listen` in direct mode: the interface, its broadcasts as well | `[dhcp] port` (67) | `[dhcp] workers` |
| `proxy` | `[dhcp] proxy`: a proxy DHCP listener answering PXE clients with boot information and no address (section 16.2) | `[dhcp] proxy_port` (4011) | 1 |

The leases, the release and the history go through the node-command interface (`tenko_dhcp::role::DhcpNode`): local on the one node of Phase 3, the same kinds over the command stream to a remote `dhcp` node in Phase 5. The API executes a command in place and records it as a row of `cluster.node_commands` in the state it reached, through an inline job, with the audit record in the same write.

| Kind | Route | What the role does |
|---|---|---|
| `dhcp.leases.list` | `GET /dhcp/leases`, `GET /dhcp/leases/{addr}`, `GET /nodes/{id}/dhcp/leases` | A page of the lease table in VRF and address order, by scope, address text, MAC, name or state, with each row's revision, whether it is the client's reservation and the reservation's host; audited `dhcp.lease.read` |
| `dhcp.lease.release` | `POST /dhcp/leases/{addr}/release`, `POST /nodes/{id}/dhcp/leases/{addr}/release` | An active lease becomes `released` now with a history row of kind `reclaimed`, under a version precondition, so that a commit of the role in between makes the release fail with `dhcp.lease.state` instead of being overwritten; `dhcp.lease.not_found`, `dhcp.store_refused` (503); audited `dhcp.lease.release` with the reason |
| `dhcp.history.read` | `GET /dhcp/history`, `GET /nodes/{id}/dhcp/history` | A page of `dhcp.history`, newest first, by address, MAC, scope, kind and time (both ends inclusive); audited `dhcp.lease.read` |
| `dhcp.stats` | | The engine's counters, the committer's, the queue, the offers held, the table's size |

A list shows only the leases and events of the scopes the caller may read. A server without the role answers 409 `dhcp.node.not_dhcp`. A released client keeps its address until it renews, is refused and starts again; the address is free for the allocator at once.

### 10.6 Health rows and metrics

`GET /system/status` carries the role's health rows:

| Code | When |
|---|---|
| `dhcp.role.not_serving` | The role answers no request: `[dhcp] listen` is empty, or it stopped |
| `dhcp.role.store_refused` | The store refuses the role's lease writes (P3-Q14): renewals are answered for the time they have left, new requests are dropped; cleared at the next commit |
| `dhcp.probe.missing` | The Hardened profile expects conflict detection (TGL-16) and no `probe` role runs in the process |

The families of `docs/dhcp-contracts.md` section 8 are registered under their names (`tenko_dhcp::role::metrics`): the engine's per-worker counters summed when the registry is read (`tenko_dhcp_packets_total{family="v4",type,outcome}`, `tenko_dhcp_exchange_duration_seconds{step}`, `tenko_dhcp_naks_total`, `tenko_dhcp_declines_total`, `tenko_dhcp_dropped_total{reason}` with the lease path's own drops added), the lazy gauges computed from the table at that time (`tenko_dhcp_leases{state}`, and `tenko_dhcp_pool_utilization{scope}` as the active bindings in the pools over the pools' addresses, by the scope's network), the lease path's `tenko_dhcp_commit_duration_seconds` and `tenko_dhcp_store_refused_total`, and `tenko_dhcp_expired_total`, `tenko_dhcp_history_rows` and `tenko_dhcp_history_purged_total` of WP7.2. The conflict and DDNS families read zero until WP8.5 and WP8.3 count them.

### 10.7 Tests

- `crates/tenko-dhcp/tests/role.rs`: the role over the in-memory store and a relay listener on loopback: the image built before the listener answers, a DORA exchange committed to `dhcp.leases` before the ACK, the four commands and the report, a scope written after the start reaching the image through the feed, and a snapshot install (the store builds the role's index aside and installs it after the role missed a scope and another node's lease) swapping image and table together while a client of the old table renews and a client of the missed scope gets a lease.
- `crates/tenko/tests/acceptance_dhcp.rs`: through the binary with `--roles controller,dhcp`: a DORA exchange relayed from loopback, the report, the lease and history routes and the system status; sixty clients, more than the store's snapshot interval, and a restart after which the renewal of the first lease is acknowledged with its address, a returning client is offered its address again and the table holds every lease; a release through the API; a role without a listener in the health view.
- `crates/tenko-dhcp/tests/direct_linux.rs` (Linux, root, ignored unless `TENKO_TEST_DIRECT_VETH=1`): a veth pair, a direct listener on one end, a client frame broadcast from the other without the broadcast flag; the OFFER arrives as a link-layer unicast to the client's MAC from the listener's address to `yiaddr`, each DISCOVER is answered once, and the link sender alone reaches the other end.
- `crates/tenko-dhcp/src/server/link.rs`: the framing of the link-layer reply against a header checksum worked out by hand.

The relay listeners with a socket per worker, the role test, the acceptance test and the direct-mode test were run on Linux on the lab node VM (Ubuntu 24.04, kernel 6.8) from binaries built in WSL; WSL itself (`networkingMode=VirtioProxy`) drops the first datagram a socket sends to a port bound after it, also outside Tenko, so tests that send a request once fail there and pass on the VM.

## 11. The lab and the measurements

### 11.1 The lab

`deploy/compose/lab-dhcp` is the topology of E23 on one Docker host: four client networks (`servers`, `lan`, `iot`, `guest`, the /26s of `192.0.2.0/24`) behind one gateway, ISC's `dhcrelay`, which relays every network to one node, the node's own network included, and routes between them. The node listens in relay mode on its unicast address, so it never sees a broadcast; it binds port 67 without a capability because its network namespace opens the low ports to its user. The clients are ISC's `dhclient` and BusyBox's `udhcpc`; the tester runs Kea's `perfdhcp` and `relay-test.py`, a relay agent of a few lines that sends option 82 with a circuit-id and, when asked, the link selection sub-option or option 118. Everything but the node comes from Debian's packages.

`smoke.sh` sets the node up through the API (the four networks as prefixes, a pool and a scope each, options 3, 6, 15 and 42) and checks, one row each: a lease on every network from the right scope with the options of E23; `giaddr` and the circuit-id on the lease row; the link selection sub-option choosing another network's scope with option 82 echoed; perfdhcp and udhcpc; the renewal at T1 through the gateway; a reservation winning over a dynamic lease; a deny filter and its removal; a release reaching the lease row; a restart of the node keeping the leases and the clients' addresses. With `NODE=example` the engine's example server is the node and only the tester's rows run (its one scope is selected by option 118 or link selection only). The weekly CI job `dhcp-lab` runs the smoke with the binary built from `deploy/Dockerfile`. The lab's README lists the services, the addresses and the commands.

### 11.2 The measurements

`bench/phase3-dhcp` holds the procedures and the results of plan section 6. `scripts/run-loopback.sh` (WP7.3) runs the engine's example server against its own load client; `scripts/run-perfdhcp.sh` (WP7.6) runs perfdhcp against the binary (`--kind tenko`, every lease committed to the store before the ACK) or the example (`--kind example`), on loopback or from the load VM to the node VM over the link: M26 as a ladder of offered 4-way rates per worker count with the ceiling at 0.1 percent drops, M27 as a ladder of renewal rates, M28 as the 50th and 99th percentile of DISCOVER to OFFER and REQUEST to ACK at 1,000 and 5,000 per second from perfdhcp's packet timestamps, with DISCOVER to ACK from the own client beside them. Every rung runs twice against a fresh server and the better run counts; the script refuses a dynamically linked binary on Linux, records the machines, the kernel, perfdhcp's version and the sysctls, and raises the load host's UDP sysctls only for the run (`bench/phase2-dns/scripts/tune-udp.sh`). Loopback figures are upper bounds; every figure is a single-node figure; Kea's and ISC's published figures compare only with the caveats of plan section 6, which the bench README repeats. The results files are under `bench/phase3-dhcp/results/`.

The first figures on the lab VMs ([2026-10-22-m26-m28-perfdhcp.md](../bench/phase3-dhcp/results/2026-10-22-m26-m28-perfdhcp.md)): the binary, every lease committed to the store, answers perfdhcp from the load VM at about 10,000 4-way exchanges per second within 0.1 percent drops, with a p99 from REQUEST to ACK of 19 ms at 1,000 per second and about 126 ms at 5,000; the commit is nearly all of that time, and DISCOVER to OFFER stays below a millisecond. Both are clear of the fallback line of P3-Q1 (section 8.2 and [ADR 0019](adr/0019-dhcp-data-model-and-lease-path.md)). The engine without the store answers 20,000 per second to perfdhcp on the same VM and about 106,000 to its own client.

### 11.3 The fuzz targets

Beside `dhcp_v4` (the whole message, WP7.1a), two targets cover the parsers relayed traffic reaches first, with seeds under `fuzz/seeds/` and a place in the weekly fuzz smoke (E31, the DHCPv4 part):

- `dhcp4_options` feeds an options area behind a fixed header (the first octet can put 192 octets into `sname` and `file` for option 52) and checks `Message::option` and `option_data` against the instances the walk yields (one instance, a split, the RFC 3396 concatenation in walk order), then runs every typed parser on the joined value with its invariants: the lengths it counts, the sub-options and length-prefixed instances it walks to the last octet, the routes and the search list encoded again.
- `dhcp4_relay_info` feeds option 82 as a relay sends it, the first octet choosing the request around it (message type, `giaddr`, option 118, `ciaddr`): the sub-option parser walks every octet and its accessors return the first instance of their sub-option, the value reads back from the request also when split, scope selection follows the order of section 9.1 (link selection, option 118, `giaddr`, `ciaddr`, the listener), and a reply carries the value back unchanged.

## 12. Reservations, the move step and observations

WP8.1 joins the `dhcp` role to the IPAM side of plan sections 2.3 and 2.8: reservations come from intent, a move of a `reserved` host gets its DHCP step done by Tenko, and every lease change is an observation in the same commit (decision P3-Q8, DHCP-16, IPAM-18, IPAM-19).

### 12.1 Reservations from intent

A reservation is not a row of its own. The configuration image (section 3, `tenko_dhcp::config::image`) derives it from a host of mode `reserved`: each live interface with a MAC address or a client identifier and each of its live IPv4 addresses of status `active` or `planned` inside a served scope give the reservation of that address for that client. A `reserved` host without a MAC address or client identifier gets the warning of IPAM-18 and no reservation. Changing the host, the interface or the address in IPAM is changing the reservation; the role's image follows the store a moment later (section 10), and the status route reports the revision of the image it serves.

**Reserving an address.** `POST /api/v1/addresses/{id}/reserve` writes the rows a reservation is derived from in one plan, one store batch and one audit record `ipam.address.reserve` (DHCP-01): the host becomes `reserved` (the host named by `host`, a new host named by `new_host` in the default tenant, else the host of the address's interface), the interface gets `mac` and `client_id` (the interface named by `interface`, a new one named by `new_interface`, else the address's interface on that host, else the host's only interface, else a new `eth0`; `client_id: null` removes one), and the address is bound to that interface with `status` `active` or `planned` (an active or planned address keeps its status; IPAM does not take an active address back to planned). `POST /api/v1/addresses/reserve` does the same for an address named by `ip` and `vrf`, for example from a lease, and creates it on the interface when IPAM does not hold it. Each change is pinned to the revision the route read, so a change made in between answers 412 `ipam.revision_mismatch` instead of being overwritten. The plan then checks what the image would find: the address lies in a prefix with a scope, enabled or not (404 `dhcp.scope.not_found` otherwise), the interface has a client identity (409 `dhcp.reservation.no_identity`, IPAM-18), and no other `reserved` host holds the address or presents the same identity in the scope (409 `dhcp.reservation.conflict`, IPAM-23, with `address` or `client` and `hosts`). IPAM's rule that a reserved host has no address inside a DHCP pool applies as for every reserved host (409 `ipam.address.in_dhcp_pool`). A refusal writes nothing; a request that finds the reservation in place answers `unchanged` and writes nothing either. The route asks the authorizer for exactly the IPAM writes it makes (`update` on an existing host, interface and address, `create` on a new one; `update` on the address when nothing changes) and no DHCP permission, takes `dry_run` and `acknowledge` like every IPAM write, and takes no `Idempotency-Key`. `tenko ipam address reserve ID_OR_ADDRESS [--vrf ID] [--host ID_OR_NAME | --new-host NAME] [--interface ID | --new-interface NAME] [--mac MAC] [--client-id HEX | --clear-client-id] [--status active|planned] [--dry-run]` calls it.

### 12.2 The move step

A move (see [moves.md](moves.md)) writes the new address as `planned` on the interface in its first step and keeps the old one until its cleanup, so during the move the interface holds both addresses and both scopes hold a reservation, as IPAM-19 asks.

| Situation | Step `ipam.move.dhcp` | Preview kind |
|---|---|---|
| `reserved` host, the target prefix has an enabled Tenko scope (IPv4), the interface has a MAC address or client identifier | Automatic: waits until the role's image is at the revision of the new address, then done; at most 60 seconds, else 503 `ipam.move.dhcp_not_served` and the job rolls back | `dhcp.reservation` |
| `reserved` host otherwise | A task for a person, as in Phase 1 | `dhcp.manual` |
| Other modes | No DHCP step | |

The step reaches the role through `tenko_ipam::moves::dhcp::DhcpRolePort` (the role's report `dhcp.status` and the node command `dhcp.lease.release`), which `tenko serve` fills once the role runs. A server without the role in its process has nothing to wait for: the step records that the reservation is intent (`image_revision` empty in its output). The step's output (`MoveDhcpOutput`) keeps the revision of the new address and the image revision that held it.

- **Rollback.** The intent step's compensation removes the new address, and with it the new reservation; the DHCP step's compensation releases a lease the device already took at the new address. The old address and its reservation were never touched, so a cancelled move leaves both scopes as they were.
- **Cleanup.** The cleanup removes the old address, which removes the old reservation, and releases the old lease when the moved interface's MAC address still holds it bound, through `dhcp.lease.release` with its version precondition (history kind `reclaimed`). A release that fails is logged and left to the lease's expiry; the cleanup never rolls a confirmed move back. Its output records `released_old_lease`.
- **Timeout.** The observation timeout keeps IPAM-19's rule, half the target's lease time and at least 300 seconds. With a Tenko scope the lease time is the longest default time a pool's client gets: the pool's settings, else the range's `lease_secs`, else the scope's lease times, else the server's (one day by default); a scope without a pool counts its own.

### 12.3 Leases as observations

The committer adds the IPAM facts of the source `dhcp:<node>` to the batch of every lease change it builds, and the operator's release (`dhcp.lease.release`) to its own batch: the lease row, the client index, the history row and the facts commit together, so there is no second write and no polling. The rules live in `tenko_ipam::observe::dhcp` (`LeaseFacts`); the hook is `tenko_dhcp::lease::observe::IpamObservations`.

| Fact | Subject | When |
|---|---|---|
| `Observed::Address` with the address and the client's MAC address | `address:<vrf>/<ip>` | The lease binds |
| `Observed::Name` with the FQDN of option 81, else the host name of option 12 | `name:<ip>` | The lease binds and the client sent a name |
| `Observed::Address` with the MAC address that answered the conflict probe (an ARP answer), else none (ICMP, a DECLINE) | `address:<vrf>/<ip>` | The row is `abandoned` (a conflict of WP8.5), until its hold ends |

`Observed::Os` and `Observed::Vendor` from the fingerprint and option 60 are section 15.3. A fact's `last_seen` is the lease's client transaction time and its `expires_at` the end of the binding when the fact was written, so a binding that runs out takes its facts with it and expiry writes nothing.

The rules of `observe::ingest` apply to each fact: a new subject is a new fact; a known fact is written again only when its attributes changed (another MAC address, another name; another device on the address starts its fact again), when it had expired, or when its refresh is due, that is 15 minutes since its last sighting or less than half of the fresh lifetime left. A renewal or a repeated request within the refresh interval writes nothing. A client renews at half its lease time, so a renewal at that point usually finds the refresh due once the lease is longer than half an hour, and writes the fact with the new sighting into the batch it writes anyway. A release, a decline or an operator's release expires the current facts of the address at once. Every outcome is counted in `tenko_dhcp_lease_facts_total{outcome}` (`new`, `changed`, `refreshed`, `unchanged`, `expired`; the address fact and the name fact count separately).

The rules need the stored facts, and the committer builds a batch without waiting on a store read. `LeaseFacts` is therefore a derived index of the store over `ipam.obs.facts`: it holds the facts of its own source in memory, built at registration and on a snapshot install, and follows every change of the table. The role is the only writer of its source, so its fact writes carry no version precondition and a lease change never fails on its observation. Each fact costs a few hundred bytes of memory in the index.

A new fact wakes the reconciler like any write to the facts table; its run confirms a move waiting at its observation step when a current lease fact comes from the moved interface's MAC address at any address of the target network ([reconciliation.md](reconciliation.md) section 7).

### 12.4 Tests

- `crates/tenko-ipam/src/observe/dhcp/tests.rs`: a renewal within the refresh interval writes nothing and is counted, the refresh at the renewal point adds a sighting, another client starts the fact again, a release expires both facts, a conflict names the answering MAC address, and the index is built from the stored facts of its own node only.
- `crates/tenko-ipam/tests/move_dhcp.rs`: the preview kind and the timeout from the scope, the step that waits for the image (and the rollback when the image stays behind), the cleanup that releases the device's old lease and no other, the compensation that releases a new lease, and the lease of a dynamic device in the target's pool that confirms its move.
- `crates/tenko/tests/acceptance_move.rs`, E25: the five-device lab through the binary with the role in relay mode on loopback.

## 13. DDNS

Tenko DHCP writes the names of its clients into the zones Tenko serves (DHCP-13, ADR 0020, plan section 2.9). The update is a change set through the zone service with the RRset origin `dhcp`; no RFC 2136 message and no TSIG key are involved, and TGL-09 (dynamic updates from external clients) does not govern it. Updates to Windows DNS or another server are Phase 4 (CONN-13, DNS-28). This section is for operators who turn DDNS on and for reviewers of `tenko_dhcp::ddns`.

### 13.1 Turning it on

DDNS needs the DNS module next to the DHCP module. Per scope, the DDNS settings (`ddns` of the scope, defaulting to the server's `dhcp.settings.ddns`); a policy can set its own for the clients it matches (section 16), and those win:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | off | Whether the server writes names for the scope's clients |
| `forward_zone` | none | The zone the names go under; none: the zone whose apex is the scope's domain name (option 15), if Tenko serves it as a primary zone |
| `reverse` | on | Whether PTR records are written, in the most specific primary zone Tenko serves that is a reverse zone of the address (plain or RFC 2317) |
| `ttl` | none | The TTL of the records; none: a third of the lease time |
| `conflict` | `protect` | `protect`: a name that belongs to another client is refused (RFC 4703); `replace`: the last client wins. Hardened always protects, and refuses `replace` at the write |
| `client_may_update_a` | off | A client that asks to write its A record itself (option 81 with S clear, or N set) does so; the server writes the PTR only |
| `legacy_clients` | on | Clients without option 81 get their option 12 host name ("update for legacy clients") |
| `refuse_foreign` | off | A name outside the forward zone is refused instead of cut to its first label under the zone |

Each zone decides whether it takes DHCP updates: the zone's update policy has `dhcp` (true, false, or unset to follow the security profile, P3-Q6).

| Profile | A zone with `dhcp` unset | Name protection |
|---|---|---|
| Home | takes DHCP updates | per scope |
| Standard | does not; set `dhcp: true` on the zone | per scope |
| Hardened | does not; set `dhcp: true` on the zone | always: the configuration service refuses `replace` in a scope's, a policy's or the server's DDNS settings (`dhcp.ddns.invalid`, field `ddns.conflict` or `action.ddns.conflict`), and the worker treats a `replace` stored before the profile changed as `protect` |
| Lab | takes DHCP updates | per scope |

The rule applies to the forward zone and to the reverse zone alike. A refused zone shows on the lease as the reason and in `tenko_dhcp_ddns_total{outcome="refused"}`.

### 13.2 Names

The name of a lease, in this order:

1. The name of option 81 (RFC 4702), lowercase. A single label goes under the forward zone (`laptop` becomes `laptop.lan.example.test`); a name below the zone stays as it is; a name outside the zone (or the apex itself) is cut to its first label under the zone, or refused with `refuse_foreign`.
2. Without option 81, the host name of option 12, when `legacy_clients` is on; a host name with dots counts by its first label.
3. Otherwise no name.

Every label keeps to the host-name rules (letters, digits and hyphens, 1 to 63 octets, no hyphen at either end); a name with another label (an underscore, say) is refused rather than rewritten.

### 13.3 What is written

For a lease with a name, as soon as its commit is durable:

| Record | Where | Data |
|---|---|---|
| A | the forward name | the lease's address |
| DHCID | the forward name | RFC 4701: identifier type, digest type 1 (SHA-256), and the SHA-256 of the client's identifier followed by the name in wire form; the identifier is `htype` and `chaddr` (type 0), option 61 (type 1), or the DUID of an RFC 4361 option 61 (type 2) |
| PTR | the reverse name of the address | the forward name |

The A and DHCID sets are one change set in the forward zone; the PTR is a change set of the reverse zone, written at the same time. A forward name that is refused gets no PTR. Where the client writes its A record itself (`client_may_update_a`), only the PTR is written. The lease row keeps the option 81 flags the client sent (`fqdn_flags`) for this decision.

The DDNS settings a lease is written by are those its reply's option 81 used: the first matching policy's that sets them (WP8.4's matcher at the REQUEST), else the scope's. The engine records the policy's settings on the lease row at the commit (`ddns_policy`; absent when the scope's apply, and kept on a release or an expiry for the same client), and the worker takes them from the row, so a policy that turns DDNS off for a vendor class keeps its clients out of the zones while the scope has it on, and one that turns it on writes names where the scope has it off. A policy edited later applies from the client's next REQUEST.

The reply's option 81 says what the server does (RFC 4702 section 4): S when the server writes the A record (and O when that overrides the client's wish), none of S, O and N when the client writes it, N when DDNS is off for the scope. The reply leaves before the update runs, so a name refused later shows on the lease, not in the reply.

### 13.4 Who may replace what

| What is at the name | A and DHCID | PTR |
|---|---|---|
| nothing | written | written |
| `dhcp`, the client's DHCID | replaced | replaced |
| `dhcp`, another client's DHCID, or a `dhcp` A without one | refused (`protect`), taken over (`replace`) | replaced: the PTR belongs to the address |
| `ipam` | taken over only where the zone's `may_replace_ipam` allows it, else refused | the same |
| `manual`, `dynamic`, `transfer`, `dnssec`, `ad` | refused | refused |
| a CNAME | refused | refused |

An address that IPAM names (an IPAM address object with a DNS name, such as a `reserved` host's) gets no DDNS at all: the DNS actuator writes its records with the origin `ipam`.

On release (a DHCPRELEASE or an operator's release), on expiry, and when a lease's name or client changes, the names the lease wrote are removed: the lease's A record (and the DHCID with the last address of the set) only while the DHCID at the name is still the client's, and a `dhcp` PTR that points at the lease's name. Another client's records and records of another origin are never touched. A client refused by name protection gets the name on its next renewal after the holder's names are gone.

### 13.5 The worker

The DDNS worker is the leader service `dhcp.ddns`, registered by the `dhcp` role (one per cluster; on one controller it runs at once). It follows `dhcp.leases` by a store watch, so every committed change reaches it after the commit and the DORA path is not involved: a client is never kept waiting for DNS, and a name appears a moment after the ACK. Each changed row becomes a request in a queue sized at start (`tenko_dhcp_ddns_queue` counts the waiting ones); the worker takes the requests in batches (the first change waits 100 ms for others to join, so that a burst of commits becomes a few change sets) and writes one change set per zone. A zone write that the store refuses is retried with a doubling pause (`[dhcp.ddns] retries`, default 5, and `backoff_ms`, default 1,000); a change set refused as a whole is applied lease by lease so one lease cannot hold up the others. A failed lease is tried again after 30 s; a refused one on its next change. A change of the DHCP configuration or of a zone makes the worker read every lease again, so turning DDNS on or allowing a zone takes effect for the leases already held.

The outcome is written to the lease row (`ddns` in `GET /dhcp/leases/{addr}`): `forward` and `reverse` (the names held), `dhcid`, `last_error` (the refusal, the failure, or why there is no name, in English) and `updated`. The row is written with its version as precondition, so a newer commit of the lease is never overwritten. `tenko_dhcp_ddns_total{outcome}` counts `written`, `removed`, `refused`, `failed`, `skipped` (no name to write: IPAM names the address, the scope names no zone) and `dropped` (the queue was full; the rows are read again). Each change set is audited by the zone service (`dns.record.change`, principal `system:dhcp`) and journalled, so IXFR to secondaries carries it; a signed zone is signed again by the signer's incremental pass.

### 13.6 Tests and measurements

- `crates/tenko-dhcp/src/ddns/`: the RFC 4701 examples of section 3.6 for the three identifier types, the name rules, the reply flags.
- `crates/tenko-dhcp/tests/ddns.rs`: the worker over the in-memory store: names on commit, name protection, removal on release and expiry, the zone switch under Standard, IPAM's names, a manual record, `replace` and the client that writes its own A record, Hardened's forced protection, and a policy's DDNS settings winning over the scope's both ways. `tests/classes.rs` checks that the engine records the policy's settings on the lease row; the configuration service's tests (`src/config/tests.rs`) the refusal of `replace` under Hardened.
- `crates/tenko/tests/acceptance_dhcp_ddns.rs` (E26 through the binary): a client with option 81 and a legacy client get their A, DHCID and PTR records served by the DNS role on ACK, a second client claiming the first one's name is refused, and the records go on DHCPRELEASE and on expiry. The lab rows of E26 (dhclient, Playwright) wait for WP7.6's lab.
- M31 (the DDNS rate end to end): `bench/phase3-dhcp/scripts/run-m31-ddns.sh` with the load client `crates/tenko-dhcp/examples/ddns_load.rs`; results in `bench/phase3-dhcp/results/`.

## 14. Conflict detection and DECLINE

Before the role offers an address that no client has had from it, it asks whether a host already uses the address, and it holds back an address a client declines (DHCP-06, TGL-16, plan section 2.7, decision P3-Q7). The code is `tenko_dhcp::conflict`; the probe contract is `tenko_dhcp::probe::ConflictProbe` (`docs/dhcp-contracts.md` section 3).

### 14.1 When an offer is probed

Only a DISCOVER's OFFER is ever probed, and only when its address has no lease history for this client and no probe found it clean within the probe cache's time. The worker that built the OFFER looks at the lease table and the cache (`conflict::rules::candidate`) and sends the OFFER at once when:

- the table holds a row of this client for the address, in any state: its own binding, an address it had and that expired or was released, its reservation once it uses it;
- the client's latest row in the scope, or in a sibling of the scope's shared network, is the address (its previous address);
- a probe found the address clean within `[dhcp.probe] cache_secs` (600 seconds).

A renewal or rebind is a REQUEST and is never probed; neither is an INIT-REBOOT or the REQUEST that follows an OFFER. A reservation its owner has not used yet is probed, and offered even when a host answers (no other address is the client's); the answer is counted and logged, and IPAM-23 reports the squatter.

### 14.2 The pending table and the cap

A DISCOVER whose OFFER waits for a probe waits in the pending table, not in a worker: the worker copies the request, the OFFER it built and where the OFFER goes into a free slot and goes on with the next datagram. The table has `[dhcp.probe] pending` slots (1,024) made at start, with its free list and its queue reserved, so parking allocates nothing (`tests/alloc.rs` measures it). A full table, or a request longer than a slot (1,472 octets), sends its OFFER unprobed and counts it.

One thread of the server, the dispatcher, with a single-threaded runtime of its own, starts a probe per parked request with the time left to the request's deadline: its arrival plus `[dhcp.probe] timeout_ms` (300 ms). The OFFER goes out:

| The probe | What happens |
|---|---|
| answered nobody within its time, or the cap cut it | The address enters the probe cache; the OFFER goes out |
| cannot run (`Unavailable`) | The OFFER goes out |
| heard the client's own MAC address | No conflict; the OFFER goes out |
| heard another host | The address is marked (14.3); the engine runs again on the same request and offers the next free address, which is probed with the time left; after three further answers the next OFFER goes out unprobed |

The dispatcher takes one timer tick off the cap (`conflict::TIMER_TICK`: 16 ms on Windows, whose system timer ticks at 15.6 ms, and 5 ms elsewhere), so no OFFER leaves later than the cap after its DISCOVER arrived. A client that sends its DISCOVER again gets the same address from the offer hold, and the cache lets it through at once.

### 14.3 A conflict

An answer from another host marks the address at once: the offer table holds it for no client (so no other worker offers it in the meantime), and a lease change of kind `conflict` writes an `abandoned` row that ends after `[dhcp.decline] hold_secs` (86,400 seconds, Kea's default probation period) with the answering MAC address as the row's hardware address when ARP gave one. The allocator skips the address until the row ends, the history shows the event, and the counters `tenko_dhcp_conflicts_total` and the role's log line (`the conflict probe found an address in use before an offer`) say so.

The abandoned row is the conflict observation of IPAM-23: `conflict::observation::conflict_observation` gives the fact of the source `dhcp:<node>`, `Observed::Address` with the address, its VRF and the answering MAC address when known, valid until the hold ends. It has the subject of the address's lease fact, so it replaces it; IPAM's reconciler compares it with the other sources and with intent and never resolves the conflict on its own. The observation hook of the lease batch (WP8.1) writes it with the lease row, so the fact is as durable as the row.

### 14.4 The probe

`conflict::scan::ScanProbe` uses the methods of the `probe` role in the same process, so the `dhcp` role needs no privilege of its own:

- **ARP** where this node sits on the address's link, that is, an interface with an IPv4 network that holds the address: an ARP request through `tenko-scan`'s raw link (`AF_PACKET`, Linux with `CAP_NET_RAW`, `docs/scanning.md` section 9), sent again halfway to the deadline and at most 100 ms in. Any ARP frame whose sender is the address, from a usable MAC address other than this node's, is an answer. The link of an interface opens on the first probe and closes after ten idle seconds.
- **ICMP echo** otherwise (relayed scopes, no `CAP_NET_RAW`, Windows): `tenko-scan`'s pinger, an unprivileged ICMP datagram socket on Linux when `net.ipv4.ping_group_range` admits the process, else the `ping` command; `ping.exe` on Windows. A reply is an answer without a MAC address; a host that drops ICMP is not seen.

The role says once per start which it uses (`the dhcp role probes an address never leased to the client before it offers it`, with the method), or that conflict detection is off.

### 14.5 When it runs (TGL-16)

| Profile | Default | Without a probe role |
|---|---|---|
| Home | On | Off, one log line per start |
| Standard | On | Off, one log line per start |
| Hardened | On | Off, one log line per start and the health row `dhcp.probe.missing` |
| Lab | Off | Off, one log line per start |

"On" means on when a `probe` role runs in the process and can use ICMP or ARP; the setting `conflict_detection` of `PUT /dhcp/settings` overrides the profile's default and takes effect without a restart. The profile's default is read when the role starts.

An installation made by `deploy/install.sh` gets the role from the installer's question or from `--roles` (any combination of `controller` with `dns`, `dhcp` and `probe`), and the installer puts the drop-in `deploy/systemd/probe.conf` (`CAP_NET_RAW`, for ARP and the raw scan methods; ICMP needs nothing) in `/etc/systemd/system/tenko.service.d/` with the role and removes it when `--reconfigure --roles` drops the role. By hand: add `probe` to `roles` in `tenko.toml` and install the drop-in as that file (or run the installer again, which reads the kept roles and installs it), then restart the service.

### 14.6 DECLINE

A DECLINE from the client that holds the address abandons it for `[dhcp.decline] hold_secs` (the engine, section 9.2): the row belongs to no client, so the allocator offers it to nobody, the decliner included, and the client gets another address on its next DISCOVER. The probe cache forgets the address, the abandoned row is the conflict observation (14.3, without a MAC address: the client does not say who answered it), and the role writes the audit record `dhcp.decline` with the scope, the address, the client's MAC address and the hold time (principal `system:dhcp`).

A client may decline at most `[dhcp.decline] limit` addresses per `window_secs` (3 per hour). A DECLINE beyond the limit is dropped (`tenko_dhcp_dropped_total{reason="rate_limited"}`) and the client keeps the lease it holds, so a broken client that declines every address it is offered cannot drain a pool. The limit is a fixed table of clients made at start; it allocates nothing.

### 14.7 Metrics and settings

| Key | Default | Meaning |
|---|---|---|
| `[dhcp.probe] timeout_ms` | 300 | The cap from the DISCOVER to the OFFER, 10 to 1,000 ms |
| `[dhcp.probe] cache_secs` | 600 | How long a clean result is kept, 0 to 86,400 s |
| `[dhcp.probe] pending` | 1,024 | Offers that may wait for a probe at once, 16 to 65,536 |
| `[dhcp.decline] hold_secs` | 86,400 | How long a declined or squatted address stays abandoned |
| `[dhcp.decline] limit`, `window_secs` | 3, 3,600 | DECLINEs per client and window |

`tenko_dhcp_conflicts_total` counts the answers from other hosts, `tenko_dhcp_probe_duration_seconds` each probe from its start to its outcome, `tenko_dhcp_declines_total` the DECLINEs received and `tenko_dhcp_dropped_total{reason="rate_limited"}` those dropped by the limit. `DhcpServer::conflicts().stats()` has the finer counters (parked, unparked, clear, capped, unavailable, own MAC, reserved, cached, limited).

### 14.8 Tests and measurements

- `crates/tenko-dhcp/tests/conflict.rs`: over loopback with a fake probe that answers at once, late or never: the OFFER on the answer and at the cap, a late answer that marks nothing, an answer that abandons the address with the squatter's MAC and offers the next, every address answering, the client's own MAC, the rules of when (renewals, the client's lease, its previous address, a reservation in use), a reservation that answers, no probe and the setting off, a full pending table, the DECLINE hold, the audit report and the limit, forty DISCOVERs on one worker all answered at about the cap, M35's first half, and the production probe over ICMP on the host.
- `crates/tenko-dhcp/tests/alloc.rs`: the worker's step (the rules, the park, the DECLINE limit and its report) allocates nothing.
- The unit tests of the probe cache and the DECLINE limit in `src/conflict/`.

M35 (plan section 6) is in `bench/phase3-dhcp/results/2026-10-22-m35-conflict-probe.md`: the offer delay for new addresses stays at most the cap and renewals are not delayed, and a squatter on the node's link is found in 20 of 20 tries, by ARP and by ICMP.
What the engine leaves to later packages: the conflict probe before an offer and the DECLINE rate limit and observation (WP8.5); classes and policies, the class restrictions of scopes and pools included (WP8.4: the image carries them and the engine does not match them yet); DDNS (WP8.3); the link-layer reply and the role's wiring, configuration and metrics registration (WP7.5).

## 15. Fingerprinting and the reconciliation view

WP8.2 reads what a client's request says about its system (DHCP-14) and joins the leases to the reconciliation view of IPAM-21, where they meet intent, the DNS records and the scans (decisions P3-Q8 and P3-Q15).

### 15.1 The fingerprint

A fingerprint is what a request shows of the client's DHCP stack (`tenko_core::dhcp::Fingerprint`): the parameter request list of option 55 in the client's order, the vendor class of option 60, and whether the client sent options 77 (user class), 81 (client FQDN) and 93 (client architecture, its first value). The DORA path copies these into the fixed-capacity change (`PendingFingerprint`) without allocating; the committer builds the owned fingerprint of the lease row (`fingerprint` on `Lease`). A row the feed copies without a fingerprint keeps the one it had. `tenko_dhcp::fingerprint::fingerprint_of` reads the same from a parsed message.

### 15.2 The rule table

The rule table (`crates/tenko-dhcp/src/fingerprint/table.rs`, `table::ENTRIES`) is written in the project, offline, from captured requests and published descriptions of client behaviour (P3-Q15; p0f's signatures describe TCP/IP stacks, not DHCP requests, and were set aside). An entry says what a fingerprint must show and what it means:

| Field | Meaning |
|---|---|
| `list` | `Exact` (the list in the client's order), `Prefix` (the list starts with these codes), `Any` |
| `vendor` | `Exact`, `Prefix`, `Contains`, `Absent` (no option 60), `Any` |
| `user_class`, `client_fqdn`, `architecture` | the presence of option 77, 81 or 93 required or excluded, or not looked at |
| `family`, `version` | the guess; a version can take the rest of the vendor class after its prefix (`android-dhcp-13` gives Android 13, `udhcp 1.35.0` gives BusyBox udhcpc 1.35.0) |
| `confidence` | 0 to 100; below 50 a family guess, not a version |
| `provenance` | `Captured` in the lab, `Modelled` in the WP7.3 corpus, `Published` |

`RuleTable::builtin` tries the entries with an exact list first, then those with a list prefix, then those without a list, each group in the order of the table, and the first that matches wins: a known release is named exactly, a later release of a known stack falls to its family, and a vendor class alone gives the weakest guess.

The table has 38 entries:

| Family | Entries | Source |
|---|---|---|
| Windows | 10 and 11 (and Server 2016 and later), 7 and 8 (and Server 2008 R2 to 2012 R2), XP (and Server 2003), a list prefix for later releases, `MSFT 5.0` alone | the WP7.3 corpus (modelled) and published lists |
| macOS, iOS and iPadOS | macOS 13 and later, 11 and 12, 10.x; iOS 15 and later, 14, 10 to 13; a list prefix for Apple | the corpus (macOS 14) and published lists |
| Android | Android 13, 11 and 12, 9 and 10 by their lists, a list prefix, the vendor class `android-dhcp-` alone, each with the release from the vendor class | the corpus (Android 13) and published lists |
| Linux | ISC dhclient (Debian and Ubuntu), systemd-networkd, NetworkManager (Fedora and RHEL), BusyBox udhcpc with and without its vendor class, dhcpcd, a dhcpcd host with a Proxmox VE kernel, a list prefix for dhclient | dhclient and udhcpc captured in the lab, networkd modelled, NetworkManager from its source |
| ChromeOS, PlayStation, Xbox | one entry each, with low confidence for the PlayStation's short list | published |
| Printers | HP JetDirect by its vendor class | published |
| Embedded | lwIP (ESP8266, ESP-IDF, Tasmota, ESPHome) with and without DNS and SNTP | lwIP's `dhcp.c` |
| Boot firmware | iPXE (QEMU and Proxmox VMs boot through it), UEFI HTTP boot, UEFI PXE x64, BIOS PXE, by option 60 with option 93 | the corpus (both PXE requests) and published |

The captured requests are fixtures in `crates/tenko-dhcp/src/fingerprint/captured/`: the first DHCPDISCOVER of Debian 12's ISC dhclient 4.4.3-P1 with the package's configuration and with the lab's own `dhclient.conf`, and of BusyBox 1.35.0's udhcpc, received by a UDP listener in containers of the lab's tools image on a throwaway bridge. A request list a configuration file sets (the lab's `dhclient.conf`) matches no entry, as it should.

What the table cannot tell it does not claim. Windows Server sends the request of the desktop release it shares a kernel with, iPadOS that of iOS, and a Proxmox or VMware guest that of the system inside it; only the guest's boot firmware (iPXE, PXE) and a dhcpcd host whose kernel release ends in `-pve` show more. The MAC address's vendor (OUI), which the probes report, is the better hint for virtual machines, and the reconciliation view shows it beside the guess.

### 15.3 The OS and vendor facts

The lease facts of section 12.3 gain two subjects, written by the same rules (a renewal within the refresh interval writes nothing; a release or a decline expires them; a binding that runs out takes them along):

| Fact | Subject | When |
|---|---|---|
| `Observed::Os` with the guess as text (`Windows 10 or 11 (or Server 2016 and later)`) and the confidence | `os:<ip>` | the lease binds and the rule table knows the fingerprint |
| `Observed::Vendor` with the vendor class | `vendor:<mac>` | the lease binds, the client has a MAC address and sent option 60 |

The hook `IpamObservations` hands its `LeaseFacts` the rule table at registration (`tenko_dhcp::fingerprint::classify_leases`, through `tenko_ipam::observe::dhcp::LeaseClassifier`); matching runs on the committer, never on a worker.

### 15.4 The OS field

The reconciliation view picks the OS of a device by precedence ([reconciliation.md](reconciliation.md) section 11): an inventory's own statement first (a hypervisor or Home Assistant says what it runs), then an active scan's guess (a probe's OS fingerprint), then the DHCP fingerprint's guess; within a rank the higher confidence, then the newer sighting. So a lease's options 55 and 60 fill the OS field of a host nothing else describes, an unmanaged one included, and an active scan outranks it as soon as it reports.

### 15.5 Tests

- `crates/tenko-dhcp/src/fingerprint/tests.rs`: the lab's captures and the corpus's modelled requests (Windows, macOS, Android, dhclient, networkd, PXE) classified, requests made up for other purposes not classified, an exact list before a prefix before the vendor class, every entry reachable (none shadowed by an earlier one), the families the plan names present.
- `crates/tenko-dhcp/tests/contracts.rs`: the contract's first-match rule, also as a property test.
- `crates/tenko-ipam/src/observe/dhcp/tests.rs`: the OS and vendor facts written, left alone on a renewal, changed, expired.
- `crates/tenko-ipam/tests/reconcile_view.rs` and E28 in `crates/tenko/tests/acceptance_reconcile.rs`: the view and the OS field (section 11 of reconciliation.md).

## 16. Classes, policies, PXE and UEFI

WP8.4 makes the classes and policies of section 5 decide what a client gets, and adds network boot: PXE firmware, iPXE, UEFI HTTP boot and PXELINUX, and proxy DHCP for the boot server discovery of PXE (DHCP-03, DHCP-05, decisions P3-Q12 and P3-Q16). This section is for operators who set up classes, policies and boot files, and for reviewers of `tenko_dhcp::class` and `tenko_dhcp::v4::engine::boot`.

### 16.1 How a request is matched

The classes and enabled policies are compiled into the configuration image when it is built (`tenko_dhcp::class::Matcher`); the DORA path reads no store and parses no condition. For each request the engine takes the fields a class can test from the message in one walk over its options and evaluates the policies of the selected scope, then the server's:

| Match | Field | Holds when |
|---|---|---|
| `vendor_class` | option 60 | it equals the text, or starts with it (`prefix`) |
| `user_class` | option 77 | the whole value equals the text, or one of its RFC 3004 instances does (Windows and iPXE send one plain string, ISC dhclient the plain text of `send user-class`) |
| `mac` | `chaddr` of an Ethernet client | the pattern matches, `*` for any octet (`00:00:5e:00:*:45`) |
| `client_id` | option 61 | the octets are equal, type octet included |
| `circuit_id`, `remote_id` | option 82, sub-options 1 and 2 | the octets are equal |
| `architecture` | option 93 | one of the client's architecture types is the code |
| `host_name` | option 12 | it equals the name or starts with it, ignoring ASCII case |

An option a client sends twice (RFC 3396) or with a bad length counts as absent: a class never matches half a value. A class is in the request when any of its matches holds; a policy's terms are joined by `and` or `or`, a term naming a deleted class is false and its negation true. Each class is evaluated at most once per request.

The first matching policy wins per action:

| Action | Effect |
|---|---|
| Options | An option comes from the first matching policy whose option set (`policy:<id>`) holds its code; the level sits between the pool and the reservation (section 4) |
| `range` | The client gets addresses of this range only (within the pools of the scope); when the range is full the request is dropped as `pool_full`, as Windows DHCP does. An address inside the range of a policy of the scope, or of a server-level policy, goes only to the clients that policy's range applies to |
| `lease` | The lease times of the grant, over the pool's and the scope's |
| `ddns` | The DDNS settings of the client over the scope's, as the matcher and the effective view decide them; the reply's option 81 (section 13) applies them; the DDNS worker still reads the scope's settings when it writes the names, which a follow-up changes |

Admission comes before the address: a scope that names classes serves only the clients of one of them (a sibling of its shared network may serve the client instead), a pool that names classes gives addresses only to the clients of one of them, and a restricted scope only clients the allow list admits (section 6). A client with a reservation is always served and always gets its reserved address; classes and policy ranges do not apply to it, its options and lease times do.

The cost per request is a comparison of a few octets per match of the classes the scope's policies name, on the worker's stack: the decision allocates nothing (`tests/alloc.rs`) and keeps the first 64 matching policies. `GET /dhcp/scopes/{prefix}/effective-options` uses the same matcher, so the classes, the policies and the options it shows for a client are those the engine applies.

### 16.2 Network boot

A boot client is one whose option 60 starts with `PXEClient` (PXE firmware and iPXE) or `HTTPClient` (UEFI HTTP boot). The boot settings are options of the levels a reply merges, so that they inherit and can be set per scope, per policy and per reservation like any other:

| Option | Meaning |
|---|---|
| 67 `boot-file-name` | The boot file: a TFTP path, or a URL for iPXE and UEFI HTTP boot |
| 66 `tftp-server-name`, 150 `tftp-server-address` | The TFTP server; the reply's `siaddr` (the next server) is the first address of option 150, else option 66 when it is a dotted IPv4 address |
| 43 `vendor-encapsulated-options` | PXE's vendor information; when no level sets it, a PXE client gets discovery control 8 (`06 01 08 ff`: boot from the file of this reply, no boot server discovery) |
| 209 `pxelinux-configfile`, 210 `pxelinux-pathprefix`, 211 `pxelinux-reboottime` | PXELINUX (RFC 5071); 208, the old magic option, needs a custom definition and goes out only when set |

When the levels give a boot client a boot file, the reply also carries the file in the `file` field (when shorter than 128 octets; PXE firmware reads the field, iPXE and UEFI either), `siaddr`, option 60 echoed as `PXEClient` or `HTTPClient` unless a level sets option 60 (UEFI HTTP boot ignores an offer without it), and options 66, 67 and 208 to 211 when set, asked for or not. A boot client without a boot file is answered as any other client, and a client that is not a boot client gets option 67 only when it asks for it.

The boot file per architecture is a policy per class of option 93 (RFC 4578 and the IANA registry: 0 BIOS, 6 UEFI x86, 7 and 9 UEFI x64, 10 UEFI ARM 32, 11 UEFI ARM 64, 15 and 16 UEFI HTTP boot x86 and x64, 19 UEFI HTTP boot ARM 64). iPXE's chain detection is a policy over the user class `iPXE`, ordered first, so that firmware gets iPXE and iPXE gets its script instead of loading itself again. A typical scope:

| Order | Policy | Condition | Option 67 |
|---|---|---|---|
| 1 | `ipxe` | class `ipxe` (`user_class` `iPXE`) | `http://boot.example.test/boot.ipxe` |
| 2 | `http-boot` | class `http-boot` (`vendor_class` prefix `HTTPClient`) | `http://boot.example.test/ipxe.efi` |
| 3 | `uefi` | class `uefi` (`architecture` 7 or 9) | `ipxe.efi` |
| 4 | `bios` | class `bios` (`architecture` 0) | `undionly.kpxe` |

with option 150 (or 66) on the scope naming the TFTP server. With the command line:

```
tenko dhcp class create ipxe --match '{"user_class":{"value":"iPXE"}}'
tenko dhcp class create uefi --match '{"architecture":{"code":7}}' --match '{"architecture":{"code":9}}'
tenko dhcp policy create --file ipxe-policy.json      # {"name":"ipxe","scope":"<prefix>","order":1,"condition":{"join":"or","terms":[{"class":"<id>"}]}}
tenko dhcp option set policy:<id> 67=<hex of the URL>
tenko dhcp policy set <id> --order 1 --enabled true
tenko dhcp class set <id> --match '{"architecture":{"code":7}}'
```

### 16.3 Proxy DHCP

A listener in `[dhcp] proxy` (an address, on `proxy_port`, 4011 by default) answers boot clients only and hands out no address (P3-Q16): a DISCOVER gets an OFFER with `yiaddr` 0 and the boot information, a REQUEST or INFORM (the boot server discovery of PXE 2.1, from a client that has its address from whichever server) gets an ACK with the same, sent back to the address and port it came from; option 97 (the client's machine identifier) is echoed. The scope is selected as for every request (by `giaddr`, by `ciaddr`, else by the listener's address) and must exist in Tenko for its boot options and policies to apply; its pools are not used and nothing is written. A request from a client that is not a boot client, or that its scope gives no boot file, is ignored (`not_boot_client`). One worker serves each proxy listener.

```toml
[dhcp]
listen = [{ address = "192.0.2.10", mode = "relay" }]
proxy = ["192.0.2.10"]
proxy_port = 4011
```

### 16.4 Tests and the lab

- `crates/tenko-dhcp/src/class/tests.rs`: every kind of match on the facts of a message, the plain user class of iPXE, AND and OR with negation and a deleted class, the scope's policies before the server's, the first match per action and per option, the admission of scopes, pools and policy ranges.
- `crates/tenko-dhcp/tests/classes.rs` (in the world of `tests/class_world`): through the engine, a vendor-class policy selects its range and options, a MAC-wildcard policy its lease time, a scope and a pool admit their classes only; PXE BIOS and UEFI clients get the boot file of their architecture with `siaddr`, `file`, option 60 and option 43; iPXE is chained to its script; a UEFI HTTP boot client gets its URL and option 60; PXELINUX's options go out unasked; proxy DHCP answers without an address, also through a listener on loopback; and the reservation identity of section 9.1.
- `crates/tenko-dhcp/src/image.rs` (unit test) and the corpus case `requests/windows-reserved-discover.hex`: a Windows-style request (option 61 of type 1 with the MAC) gets the reservation keyed by its MAC.
- `crates/tenko-dhcp/tests/alloc.rs`: the decision, the admission, the boot options and the proxy path allocate nothing.
- E27's class and PXE rows in the compose lab (`deploy/compose/lab-dhcp`, section 11): a vendor-class policy and a MAC-wildcard policy select their options and ranges, a user-class client gets its policy's options, QEMU with its iPXE ROM boots in BIOS mode and OVMF in UEFI mode from the lab's TFTP and HTTP server, a UEFI HTTP boot client gets its URL and fetches it, and the proxy DHCP listener answers the boot server discovery.

## 17. The home cut-over

The procedure of exit criterion E23 (WP8.7, decisions P3-Q5 and P3-Q18): the reference home network runs DHCPv4 through one Tenko node for all four of its networks. The gateway relays each network to the node's address, giaddr (and option 82 where the gateway adds it) selects the scope, the clients keep their addresses across the switch, options 6 and 42 reach them, and the rollback is one setting per network on the gateway with the old server's scopes activated again (DHCP-01, DHCP-02, DHCP-04, DHCP-15). Until the gateway relays to the node, nothing in the network changes; the old DHCP server stays installed with its scopes deactivated until the cut-over has held for a while.

Every name and address below is a placeholder. Put in your own:

| Placeholder | Stands for |
|---|---|
| `192.0.2.10` | The node's fixed address, the one the gateway relays to |
| `192.0.2.5` | The DHCP server the networks use today (a Windows DHCP server in the reference environment); it keeps running with its scopes deactivated |
| `192.0.2.0/26`, `192.0.2.64/26`, `198.51.100.0/24`, `203.0.113.0/25` | The four networks: two LANs, the IoT network and the DMZ |
| `192.0.2.1`, `192.0.2.65`, `198.51.100.1`, `203.0.113.1` | The gateway's address in each network (the router of option 3, and the giaddr of each network's relayed requests) |
| `192.0.2.53`, `192.0.2.123` | The DNS server of option 6 and the NTP server of option 42 |
| `home.example.test` | The domain name of option 15 and the zone DDNS writes into, if it is used |
| `00:00:5e:00:53:01` | A client with a reservation |

### 17.1 Before the day

Each row is done and checked before the relay changes, in this order.

| What | How | Checked by |
|---|---|---|
| A node with the `dhcp` role in relay mode | `roles = "controller,dhcp"` (or `controller,dns,dhcp`) and `[dhcp] listen = [{ address = "192.0.2.10", mode = "relay" }]` in `tenko.toml` (section 10.2; the first-run wizard's DHCP step writes this section); UDP 67 open in the host's firewall from the gateway; the node itself on a fixed address, not a lease of the server it replaces | `tenko serve` prints `dhcp role answering on 192.0.2.10:67 (relay) ...`; `GET /api/v1/nodes/{id}/dhcp` has `"serving": true` and the listener in relay mode |
| The four networks in IPAM | Each network a prefix of role network: from the spreadsheet import, or entered | The IPAM tree lists the four |
| The scopes | A scope per network (`/dhcp`, or `tenko dhcp scope create PREFIX`), each with a pool as an IPAM range of role `dhcp_pool` that covers the same addresses as the old server's scope, and the old scope's exclusions as exclusions. Equal pools let the clients keep their addresses (section 17.2) | The scope list shows four scopes with pools; each scope's utilization reads its pool size |
| The options | Option 6 (`192.0.2.53`), 42 (`192.0.2.123`) and 15 (`home.example.test`) on the server's set where they are the same everywhere, option 3 (the gateway's address of the network) on each scope; whatever else the old server set per scope (`Get-DhcpServerv4OptionValue -ScopeId 192.0.2.0 -All` lists them) | The scope's options tab shows, for a client's MAC, every option with the level it comes from |
| The reservations | Every reservation of the old server as an IPAM host of mode `reserved` with the interface's MAC address (or client identifier) and its address (section 12.1); the host page shows the reservation, the scope it falls in and whether the role serves it, and the IPAM-18 warning for a host without one | `/ipam/reconcile` and each host page's DHCP reservations block: no "no identity" row, every reservation in a served scope |
| Classes and policies | Only where the old server had policies that matter on day one (most homes need none, section 16) | The policy list |
| DDNS | Optional: turned on per scope on the scope's DDNS tab, with the zone taking DHCP updates (section 13.1) | The DDNS tile of the start page counts names written once clients renew |
| The lease time on the old server | A few days before, shorten the lease time of the old scopes to an hour (`Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -LeaseDuration 01:00:00`), so that on the day every client renews within half an hour and none holds a lease of days that the old server would still answer for. Wait one old lease time for the change to reach every client | A client's `ipconfig /all` shows a lease that expires within the hour |
| The relay | Know where each network's DHCP relay is set on the gateway (the DHCP mode of the network: server or relay, and the relay's server address). The classic controller API shows no relay targets to check (P3-Q18), so the relay is set and checked by hand (section 17.3) | Each network's setting found |

### 17.2 What the clients do

A client with a reservation gets its reserved address from the first answer. A dynamic client asks for the address it had: renewing, it asks the old server by unicast and gets no answer (its scope is deactivated); rebinding, it broadcasts, the gateway relays, and Tenko grants the address when it is free in its pool; a client that restarts (INIT-REBOOT) and gets no answer goes back to DISCOVER with its old address as the requested one and is offered it when it is free. Tenko holds no leases of the old server, so with equal pools a client keeps its address unless another client took it in between; the verification rows check a few. A client of a network whose relay is not set yet gets no answer at all and keeps its address until its lease runs out, which is why the old lease time was shortened and why the relay is switched network by network.

### 17.3 The switch

For each network, one at a time, the node's own network last:

1. Deactivate the old server's scope of the network: `Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State InActive` (on Windows; elsewhere the scope's on/off setting). The old server must never answer on a network the gateway relays to the node: two servers answering give clients conflicting offers.
2. On the gateway, set the network's DHCP to relay with the server `192.0.2.10`. The gateway then relays each network's requests to the node, giaddr naming the gateway's address in that network (`192.0.2.1` for `192.0.2.0/26`); where the gateway adds option 82, its circuit-id and remote-id go on the lease row. The node's own network is relayed too, so the node never answers a broadcast (section 2.5 of the plan, R56).
3. Check from one client of the network (section 17.4); then go on with the next network.

Where a probe node or any Linux host sits in a network, the relay can be checked without taking a lease: `nmap --script broadcast-dhcp-discover -e eth0` (or `sudo dhclient -v -d -sf /bin/true eth0`, stopped after the first offer) shows an offer whose server identifier is `192.0.2.10` and whose router is the gateway's address of that network. An offer from `192.0.2.5` means the old scope still answers; no offer at all means the relay is not set or UDP 67 does not reach the node.

### 17.4 The check from one client per network

| Client | Command | Expected |
|---|---|---|
| Windows | `ipconfig /release` then `ipconfig /renew`, then `ipconfig /all` | The address (the same as before for a reserved client), `DHCP Server . . . : 192.0.2.10`, the gateway, `DNS Servers` `192.0.2.53`, the lease time of the Tenko scope |
| Linux | `sudo dhclient -r eth0; sudo dhclient -v eth0` | `DHCPOFFER of 192.0.2.40 from 192.0.2.1` (the relay) and `DHCPACK ... from 192.0.2.1`; `ip addr` and `resolvectl status` show the address and the DNS server |
| A phone | Wi-Fi off and on, then the network details | The address, the router and the DNS server of the scope |
| The node | `/dhcp/leases` with the network's scope chosen | The client's lease, `active`, its MAC, its name, the relay's giaddr; the history shows `granted` |
| DNS | `dig @192.0.2.53 laptop.home.example.test` for a client whose name DDNS writes | The client's address; the lease's DDNS state on the lease row |

### 17.5 The first hour

The DHCP tiles of the start page show the node live (OPS-20), next to the controller's tiles:

| Tile | Healthy | When it is not |
|---|---|---|
| Leases granted | Rises as the networks are switched and the clients renew, then settles at the renewals of an hour's lease (a home of 100 clients: a few a minute) | Nothing after a network was switched: its relay does not reach the node (section 17.3) |
| REQUEST to ACK, p99 | A few milliseconds: the commit of the lease is in it | Hundreds of milliseconds: the store is slow (the controller's commit tile) |
| Active leases | Grows towards the number of clients | |
| Fullest pool | The three fullest scopes, each well below 100 percent | A pool near full: widen it in IPAM before clients are refused (`pool_full` drops) |
| NAKs and DECLINEs | Near zero; a few NAKs at the switch from clients that ask for an address of another network | Many DECLINEs: an address in a pool is used by a device with a fixed address; the conflict and reconcile views name it |
| DDNS names written | Names as clients renew, when DDNS is on | Refusals: the zone takes no DHCP updates, or a name belongs to another client (section 13.4) |

The lease list's live strip shows how full the chosen scope's pools are and how many leases were granted since the page was opened; `/ipam/reconcile` lists rogues (a lease without intent), conflicts (two MACs on one address) and ghosts; `GET /api/v1/system/status` warns with `dhcp.role.not_serving` or `dhcp.role.store_refused` when the role stops answering or the store refuses its writes: roll back at once.

### 17.6 The rollback

1. On the gateway, set each network's DHCP back to what it was (the old server, or the relay to `192.0.2.5`).
2. Activate the old server's scopes: `Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State Active`, and set their lease time back.
3. Renew the clients that matter now (`ipconfig /renew`); the others follow within half a lease time. The node keeps running with its leases and history for the follow-up; its scopes can be disabled (`enabled` off on the scope) so that a relay set by mistake gets no answer.

Roll back when a network's clients get no address, when the role stops answering, when NAKs or DECLINEs keep rising, or when the household asks for it.

### 17.7 Verification rows of E23

E23 is met when every row holds; tick each with the date.

| Done | Requirement | Command | Expected |
|---|---|---|---|
| [ ] | E23: all four networks through one node | `/dhcp/leases`, one scope at a time | Leases in each of the four scopes, written by the node |
| [ ] | DHCP-04: giaddr selects the scope | `GET /api/v1/dhcp/leases/{addr}` for a client of each network | `relay.giaddr` is the gateway's address of that network and `scope` the network's scope |
| [ ] | DHCP-04: option 82, where the gateway adds it | The same lease rows | `relay.circuit_id` and `relay.remote_id` present; otherwise giaddr alone selected, which is enough for one scope per network |
| [ ] | DHCP-01: reservations | `ipconfig /all` on a reserved client (`00:00:5e:00:53:01`) after `/renew` | The reserved address; the lease row says `reserved: true` |
| [ ] | E23: clients keep their addresses | A few dynamic clients, before and after their network's switch | The same address |
| [ ] | DHCP-02: option 6 | `ipconfig /all`, `resolvectl status` | `192.0.2.53` |
| [ ] | DHCP-15: option 42 | `w32tm /query /configuration` on a client that takes NTP from DHCP, or `dhclient -v` with `ntp-servers` requested | `192.0.2.123` |
| [ ] | E23: the rollback is one setting | Section 17.6 on one network, then the switch again | The old server answers within a renewal; Tenko again after the switch |
| [ ] | The relay check without the controller (P3-Q18) | Section 17.3, the offer from a host in each network | Server identifier `192.0.2.10`, the network's router |

Record the date, the lease times used and the findings in the Phase 3 status (`docs/plans/phase-3-status.md`).

## 18. The Kea export

WP9.3 writes Tenko's DHCPv4 and DHCPv6 configuration and leases in the form ISC Kea 2.6 reads (MIG-16, decisions P3-Q10 and P3-Q17 (a)), so that leaving Tenko is never blocked by a format only Tenko reads: `kea-dhcp4` and `kea-dhcp6` start from the export and keep the clients' addresses. This section is for operators who leave Tenko or keep a Kea server as a fallback, and for reviewers of `tenko_dhcp::export::kea`. Sections 18.2 to 18.4 cover the `Dhcp4` document, section 18.5 the `Dhcp6` document of the DHCPv6 server of section 19, section 18.6 the tests of both.

### 18.1 Running it

```sh
tenko dhcp export --format kea --leases --out kea/   # the files below, in kea/
tenko dhcp export                                    # the whole answer as JSON, no leases
```

| File | What |
|---|---|
| `kea-dhcp4.json` | `{"Dhcp4": {..}}`, the configuration `kea-dhcp4 -c` reads; check it with `kea-dhcp4 -t kea-dhcp4.json` |
| `kea-leases4.csv` | with `--leases`: the memfile lease file; copy it to `/var/lib/kea/kea-leases4.csv` before Kea starts (Kea 2.6 accepts a lease file only in its data directory) |
| `kea-export-report.json` | the loss report, `{"entries": [..]}` with `location`, a stable `code` and an English `detail` per item, the shape the migration imports report in (`tenko_core::ir::LossReport`) |
| `kea-dhcp6.json` | when a scope is on an IPv6 prefix or the role has a DHCPv6 listener: `{"Dhcp6": {..}}`, the configuration `kea-dhcp6 -c` reads; check it with `kea-dhcp6 -t kea-dhcp6.json` (section 18.5) |
| `kea-leases6.csv` | with `--leases`, beside `kea-dhcp6.json`: the DHCPv6 memfile lease file, for `/var/lib/kea/kea-leases6.csv` |
| `kea-dhcp-ddns.json` | when a scope of either family writes names: a `{"DhcpDdns": {..}}` skeleton for `kea-dhcp-ddns`, which both servers send their name changes to |

Kea runs one daemon per family, each with its own file, so the export writes one document per family rather than one file with both; the loss report and the DDNS skeleton cover both. The route is `GET /api/v1/dhcp/export?format=kea` (`leases=false` leaves the lease files out; `leases` is true when absent): `dhcp4`, `dhcp6` (absent without DHCPv6), `leases4_csv`, `leases6_csv`, `dhcp_ddns` and `losses`. An unknown format answers 400 `dhcp.export.format`, a server without the DHCP configuration service 409 `dhcp.module.disabled`. The export is server-wide configuration and the leases are personal data: the caller needs `dhcp.read` on the `dhcp_scope` singleton (global roles only), and every export writes the audit record `dhcp.export` with the format, whether the leases were included, the number of scopes, lease rows and report entries. It reads every row at one revision; the listeners of both families come from the `dhcp` role when it runs in the process. The route writes `server-id` from the server DUID of the role's status; the lab node's default is a DUID-UUID, which Kea cannot hold, so its export reports `export.kea.v6.server_id.type` (section 18.5).

### 18.2 What translates

| Tenko | Kea 2.6 |
|---|---|
| Server lease times, T1 and T2 | Global `valid-lifetime`, `min-valid-lifetime`, `max-valid-lifetime`; `calculate-tee-times` with `t1-percent` 0.5 and `t2-percent` 0.875 (half and seven eighths), `renew-timer` and `rebind-timer` where T1 and T2 are set |
| `authoritative` | Global and per subnet; one value per shared network |
| Server, shared network, scope, pool and reservation options | `option-data` at the global, shared-network, subnet, pool and reservation levels, with Kea's names; text where Kea reads text (addresses, integers, booleans, names, printable strings without a comma), else hexadecimal wire data (`csv-format` false); option 54 from the scope's server identifier |
| Custom definitions | `option-def`; the catalog codes Kea 2.6 does not define (150 `tftp-server-address`, 209 to 211, 249, 252 `wpad`) get one when used |
| Scopes | `subnet4` entries numbered from 1 in network order, with `user-context` naming the Tenko prefix; a scope of a shared network inside its `shared-networks` entry |
| Pools | The `dhcp_pool` ranges without the exclusions (explicit ones, the `reserved` and `infrastructure` ranges, addresses of hosts that are not `dynamic`), split where a policy range begins or ends |
| Reservations | Per subnet, by `client-id` when the interface has one, else `hw-address`, with `ip-address`, the host name as `hostname`, the reservation's options; `host-reservation-identifiers` client identifier first, as Tenko looks up |
| Classes | A client class per class, `test` the OR of its matches (below) |
| Policies | A class per enabled policy (`policy.<name>`, `policy.<network>.<name>` for a scope's) with its condition as `test` and its lease times; its options in a second class `<policy>.options`, `only-if-required`, named in the `require-client-classes` of every subnet the policy applies to, in Tenko's order (the scope's policies by order, then the server's) |
| Policy ranges, pool and scope classes, restricted scopes | The `client-class` of each pool piece: the client of a range policy only from its range, other clients never from a policy's range, scope and pool classes, the allow class `tenko.allow` for restricted scopes; a combination is a class `admit.<n>` |
| Deny filters | Kea's `DROP` class, the OR of the patterns |
| Boot | `next-server` from option 150 (else 66 when it is an address), `boot-file-name` from option 67, at each level; options 66, 67 and 208 to 211 of a policy `always-send`; when any level sets option 67 the class `tenko.pxe` echoes option 60 `PXEClient` and sends option 43 `06 01 08 ff` (unless an option set holds 43), `tenko.http-boot` echoes `HTTPClient` |
| DDNS (ADR 0020) | Per subnet `ddns-send-updates`, `ddns-qualifying-suffix` (the forward zone, else the scope's option 15), `ddns-conflict-resolution-mode` (`check-with-dhcid` for `protect`, `no-check-with-dhcid` for `replace`), `ddns-override-client-update` and `ddns-override-no-update` (true unless `client_may_update_a`), `ddns-replace-client-name` `never`; global `ddns-send-updates` false and `dhcp-ddns` pointing at `kea-dhcp-ddns` on 127.0.0.1:53001; the skeleton lists the forward domains and the reverse domains of the scopes with PTR records on, with the scope's first option 6 server |
| Listeners | `interfaces-config`: relay listeners as `udp` sockets with `outbound-interface` `use-routing`, direct ones as `raw`; an interface name where the listener has one, else `*` |
| Leases | `kea-leases4.csv` (below) |

The match expressions of Kea's classification language:

| Match | `test` |
|---|---|
| Vendor class | `option[60].hex == 'PXEClient'`, a prefix `substring(option[60].hex,0,9) == 'PXEClient'` |
| User class | `option[77].hex == 'iPXE' or substring(option[77].hex,0,5) == 0x0469505845`: the whole value or its first RFC 3004 instance |
| MAC pattern | `pkt4.mac == 0x00005e005301`; with wildcards one `substring(pkt4.mac,i,n) == 0x..` per run of fixed octets |
| Client identifier | `option[61].hex == 0x01..` |
| Circuit-id, remote-id | `relay4[1].hex == ..`, `relay4[2].hex == ..` |
| Architecture | `substring(option[93].hex,0,2) == 0x0007 or ..` over the first four entries of option 93 |
| Host name | `lcase(option[12].text) == 'name'`, a prefix with `substring` |

A literal is quoted text when it is printable ASCII without a quote or a backslash, else hexadecimal. `and`, `or` and `not` join the terms of a policy; a term naming a deleted class is false (`not member('ALL')`), as in Tenko. Classes come in the order Kea needs (`member()` names only classes above it): `DROP`, `tenko.allow`, the boot classes, Tenko's classes by name, the policies, their option classes, then the pool and scope classes the subnets add.

**Precedence.** Kea ranks options host, pool, subnet, shared network, class, global; Tenko ranks host, policy, pool, scope, shared network, server. Where a policy that applies to a subnet sets a code the scope or its shared network also sets, the export moves that code from the subnet (and from the shared network, keeping it on the members that do not conflict) into the class `scope.<network>.defaults`, which the subnet requires after its policies' option classes: the first matching policy wins, then the scope's value, as in Tenko. Kea evaluates required classes after the address is chosen, so a policy's lease times and range sit on its first class, which Kea evaluates on arrival.

**The lease file.** Kea 2.6's memfile columns `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id`. An `active` lease is state 0 with its client's hardware address and client identifier, the time from `cltt` to `ends` and the end; an `abandoned` one is state 1 (declined) without a client until its end; the other states hold no address and are left out. `fqdn_fwd` and `fqdn_rev` say whether the DDNS worker wrote the A and PTR records, `hostname` is the name written, else the client's; a comma is written `&#x2c` as Kea writes it.

### 18.3 The loss report

Every item Kea does not express as Tenko does is one entry; `location.sheet` names the item (`policy printers (192.0.2.64/26)`, `scope 192.0.2.128/26`).

| Code | What |
|---|---|
| `export.kea.scope.disabled` | A disabled scope is left out |
| `export.kea.scope.duplicate` | A second VRF's scope on the same network (Kea has no VRFs) |
| `export.kea.scope.restricted` | A restricted scope: its pools require `tenko.allow`, but Kea still answers other clients with a NAK or an INFORM reply |
| `export.kea.pool.lease` | A pool's own lease times (Kea's pools have none) |
| `export.kea.pool.precedence` | A pool option a policy also sets: Kea's pool level wins |
| `export.kea.class.partial`, `export.kea.policy.partial` | A user class matched beyond the first RFC 3004 instance |
| `export.kea.policy.disabled` | A disabled policy is left out |
| `export.kea.policy.class_missing` | A term names a deleted class |
| `export.kea.policy.ddns` | A policy's DDNS settings (Kea 2.6 sets DDNS per subnet) |
| `export.kea.policy.timers` | A policy's T1 and T2 |
| `export.kea.policy.lease_everywhere` | A scope policy's lease times also apply to matching clients of other subnets |
| `export.kea.policy.range` | A scope policy's range outside the scope's pools |
| `export.kea.filter.deny` | Deny filters became `DROP` |
| `export.kea.option.vendor_space` | Values of a vendor space (option 43 sub-options per vendor class) |
| `export.kea.option.subnet_mask` | Option 1 (Kea derives it) |
| `export.kea.reservation.dropped`, `export.kea.reservation.no_identity` | A reservation the image drops (IPAM-23) or cannot make (IPAM-18) |
| `export.kea.shared_network.authoritative` | Scopes of a shared network that differ in `authoritative` |
| `export.kea.interfaces.unknown`, `.address`, `.proxy` | No listeners known (the role does not run in the process), a relay listener bound to an address (Kea binds interfaces: write `<interface>/<address>`), a proxy DHCP listener |
| `export.kea.conflict_detection` | Conflict detection before an offer (Kea's core has none; its ping_check hook does) |
| `export.kea.history` | The lease history is not exported |
| `export.kea.ddns.ttl`, `.legacy_clients`, `.refuse_foreign`, `.reverse`, `.zone`, `.d2` | A TTL in seconds (Kea takes a share of the lease time), legacy clients off, foreign names refused, PTR records off in a shared reverse domain, no zone to name, and the `kea-dhcp-ddns` skeleton to complete (DNS servers, TSIG keys) |
| `export.kea.lease.scope` | Leases of scopes the export left out (either family) |

The codes of the `Dhcp6` document are in section 18.5; the scope, pool, reservation, listener, DDNS and lease codes above apply to DHCPv6 scopes too.

### 18.4 Verification

The unit tests in `crates/tenko-dhcp/src/export/kea/` cover the expressions, the options, the pools, the lab-shaped configuration with every level, class, policy and filter kind (including that every class a test, pool or subnet names is defined before it), the lease file and the report; `crates/tenko-api/tests/dhcp_export.rs` the route, its audit record and its errors; `crates/tenko/tests/acceptance_kea_export.rs` the command line through the binary. E30's DHCPv4 rows run in the compose lab (section 11, `deploy/compose/lab-dhcp`, profile `kea`, `kea.Dockerfile` with Kea 2.6 from Debian 13): after the other rows the smoke adds a policy with a DDNS action, exports with the leases, and checks:

| Row | Checks |
|---|---|
| `export.kea` | `kea-dhcp4 -t` accepts `kea-dhcp4.json` |
| `export.kea.report` | the report names the DDNS policy (`export.kea.policy.ddns`) |
| `export.kea.reservation` | with the node stopped, Kea on the node's address from the export gives client-lan its reservation `192.0.2.80` with options 3 and 6 |
| `export.kea.lease` | client-iot asks again (INIT-REBOOT) and keeps the address of its exported lease |

The DHCPv6 rows and tests are in section 18.6.

### 18.5 The DHCPv6 half

`tenko_dhcp::export::kea::v6` writes the DHCPv6 scopes of section 19 as the `Dhcp6` document, from the same image the engine serves from, so every address, lifetime and option is the one the engine would give. Classes and policies stay DHCPv4-only in Tenko (section 19), so the document has no client classes from them; the MAC filters, which the engine applies to DHCPv6 clients by their link-layer address, are the only classes it holds.

| Tenko | Kea 2.6 `Dhcp6` |
|---|---|
| Server lease times | Global `valid-lifetime`, `preferred-lifetime` (five eighths of valid), `renew-timer` and `rebind-timer` (half and four fifths of the preferred lifetime unless T1 or T2 is set, then the DHCPv4 rule scaled, both kept below the preferred lifetime), each with `min-` and `max-` set to the same value: the engine grants the configured lifetimes and none a client asks for |
| A scope's lease times and `v6.preferred_secs` | The same eight parameters per subnet, derived as the engine derives them (`v6::engine::alloc::lifetimes`; a property test holds the export's derivation to the engine's) |
| `v6.rapid_commit` | `rapid-commit` per subnet, true unless the scope turns it off (Kea's default is false) |
| `v6.interface_id` | `interface-id` of the subnet (Kea selects by it before the relay's link address, as the engine does); in a shared network on the shared network, the first one when the scopes differ (reported) |
| Relay link addresses | Nothing to write: the engine selects the scope whose network holds the link address of the relay on the client's link, and Kea selects the subnet whose prefix holds it, so no subnet needs Kea's `relay` list |
| A direct DHCPv6 listener | `interface` of the subnet whose network holds the listener's address (on its shared network when it has one; a shared network's own `interface` wins); Kea takes either `interface` or `interface-id`, so an Interface-Id beside an interface is reported |
| Server, shared network, scope, pool and reservation options | `option-data` at the global, shared-network, subnet, pool and reservation levels with Kea's DHCPv6 names (`dns-servers` 23, `domain-search` 24, `sntp-servers` 31, `ntp-server` 56, `bootfile-url` 59, `sol-max-rt` 82 and the rest of the catalog, every one defined by Kea 2.6); 23 and 24 `always-send`, as the engine sends them unasked; option 56 as hexadecimal wire data with one `NTP_SUBOPTION_SRV_ADDR` sub-option per address, the octets the engine sends (Kea defines it as an empty option over `v6-ntp-server-suboptions`); the `dhcp4` and vendor values of an option set are left out |
| Custom definitions of `dhcp6` | `option-def` of `Dhcp6`; the definitions of other spaces go to `Dhcp4` only |
| DHCPv6 scopes | `subnet6` entries numbered from 1 in network order, with `user-context` naming the Tenko prefix; a scope of a shared network inside its `shared-networks` entry |
| Pools | The `dhcp_pool` ranges without the exclusions (the image's merged list) and without the network's first address, the Subnet-Router anycast address the engine never leases; a restricted scope's pools require `tenko.allow` |
| Reservations | Per subnet, by `duid` when the interface has one, else `hw-address`, with `ip-addresses`, the host name as `hostname`, the interface's options; `host-reservation-identifiers` `duid` then `hw-address` and `mac-sources` `client-link-addr-option` then `duid`, so a reservation by MAC matches the address of the relay's option 79 (RFC 6939), else of a DUID-LLT or DUID-LL, as the engine reads it |
| Deny and allow filters | `DROP` and `tenko.allow`, each the OR of its patterns against the client's link-layer address: `relay6[0].option[79].hex` of hardware type 1 when the relay sent option 79, else the address of a DUID-LLT (`substring(option[1].hex,8,6)`) or DUID-LL (`substring(option[1].hex,4,6)`) |
| Server DUID | `server-id`: a DUID-LLT as type `LLT` with `htype`, `time` and `identifier`, a DUID-EN as `EN` with `enterprise-id`, a DUID-LL as `LL`; Kea holds no DUID-UUID, which is the derived default of `[dhcp.v6] server_duid` |
| Listeners | `interfaces-config`: a direct listener's interface; a relay listener bound to an address as `*` (reported: name it `<interface>/<address>`, the only form on which `kea-dhcp6` receives unicast) |
| DDNS | The parameters of section 18.2 per subnet; `ddns-qualifying-suffix` is the forward zone, else the first name of the scope's option 24, as the DDNS worker takes it; the skeleton gains the `ip6.arpa` reverse domain on the nibble boundary at or above the prefix length and the scope's first option 23 server; `Dhcp6` has its own `dhcp-ddns` to the same `kea-dhcp-ddns` |
| Leases | `kea-leases6.csv` (below) |
| Delegation pools (`IA_PD`, WP9.4) | `pd-pools` of the subnet of the pool's scope, each with `prefix`, `prefix-len` and `delegated-len`: the pool's prefixes of the delegated length without every prefix an excluded address lies in (the engine never delegates those), each run of delegable prefixes written as the fewest aligned prefixes that cover it, with the pool's options and, in a restricted scope, `client-class` `tenko.allow`; Kea, like the engine, offers a subnet's `pd-pools` to the clients of every subnet of its shared network |

**The lease file.** Kea 2.6's DHCPv6 memfile columns `address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id`. An `active` address lease is state 0, lease type 0 (`IA_NA`), prefix length 128, with the client's DUID and IAID, the times from `cltt` to `ends` (valid) and to `preferred_ends` (preferred) and the end; the link-layer address the engine learned is `hwaddr` with its hardware type and Kea's source bit (2 from the DUID, 8 from the relay's option); an `abandoned` lease is state 1 (declined) with Kea's empty DUID `00:00:00` until its end; an `active` delegated prefix is lease type 2 (`IA_PD`) with its first address, its delegated length as `prefix_len` and no name; the other states are left out. `fqdn_fwd` and `fqdn_rev` say whether the DDNS worker wrote the AAAA and PTR records, `hostname` is the name written, else the client's option 39 name, a comma written `&#x2c`.

**After the move.** Kea answers a client's RENEW only when it names Kea's server DUID. With `server-id` set from a DUID-LLT, DUID-EN or DUID-LL the clients renew with Kea as they did with Tenko; without it (a DUID-UUID, which is the default, or an export where the role does not run in the process; the route's export takes the role's server DUID since WP9.4) Kea makes a DUID-LLT of its own, the clients' RENEWs go unanswered, and at T2 they REBIND without a server identifier and Kea answers from the lease file, so they keep their addresses. Set `server-id` by hand from `[dhcp.v6] server_duid` to keep the renewals.

The codes of the `Dhcp6` document:

| Code | What |
|---|---|
| `export.kea.v6.classes` | Tenko's classes and policies (and the classes a DHCPv6 scope names) apply to DHCPv4 clients only; `Dhcp6` has no classes from them |
| `export.kea.v6.filters` | The MAC filters as `DROP` and `tenko.allow`: Kea reads option 79 of the relay nearest the server (`relay6[0]`), the engine that of the relay on the client's link, which differs only behind more than one relay |
| `export.kea.v6.server_id.unknown` | The server DUID is not known to the export (the dhcp role does not run in the process, or serves no DHCPv6): no `server-id` |
| `export.kea.v6.server_id.type` | A server DUID Kea's `server-id` cannot hold (DUID-UUID): no `server-id` |
| `export.kea.v6.interface_id` | An Interface-Id beside a direct interface, or several in one shared network |
| `export.kea.v6.interfaces.address` | A relay listener bound to an address: write `<interface>/<address>` in `interfaces-config` |

### 18.6 Verification of the DHCPv6 half

The unit tests in `crates/tenko-dhcp/src/export/kea/v6/tests.rs` export a configuration with every DHCPv6 level and setting (two single scopes, one restricted and selected by Interface-Id; a shared network on a direct link with two Interface-Ids; a disabled scope; reservations by DUID and by MAC with options; options 23, 24, 31, 56 and a custom definition; deny and allow filters; a class; leases active, declined, delegated, released and of a left-out scope) and compare it with the golden files `crates/tenko-dhcp/src/export/kea/fixtures/kea-dhcp6.json` and `kea-leases6.csv` (`KEA_GOLDEN=update` writes them anew for review in the diff); they check each mapping, the report and the server DUID types, and two property tests hold the lifetimes to the engine's and the pools to exactly the addresses the engine may lease. `crates/tenko-api/tests/dhcp_export.rs` checks the `Dhcp6` document and its lease file through the route, `crates/tenko/tests/acceptance_kea_export.rs` the two files through the binary. E30's DHCPv6 rows end the lab's round `dhcp6` (section 19, `ROUNDS=dhcp6`; the kea image holds `kea-dhcp6` too, `kea.sh 6` starts it, the compose service `kea6` of the profile `kea` runs it in the node's network namespace): after the other rows a DUID-EN client takes a lease on iot6 through `relay-test6`, the node exports with the leases, and the rows check:

| Row | Checks |
|---|---|
| `export.kea6` | `kea-dhcp6 -t` accepts `kea-dhcp6.json`, with `interfaces-config` naming the node's interface and address as the report asks |
| `export.kea6.golden` | `kea-dhcp6 -t` accepts the golden file of the unit tests |
| `export.kea6.report` | the report names the relay listener's address (`export.kea.v6.interfaces.address`) and the server DUID Kea cannot hold, the node's default DUID-UUID (`export.kea.v6.server_id.type`) |
| `export.kea6.reservation` | with the node stopped, `kea-dhcp6` on the node's addresses gives client-dhclient6 (dhclient -6 through dhcrelay) its reservation by DUID, `2001:db8:101::80`, with options 23, 24 and 56 |
| `export.kea6.lease` | the DUID-EN client asks again and keeps the address of its exported lease, which was not the pool's first address |

## 19. DHCPv6

WP9.1 adds DHCPv6 (RFC 8415) to the `dhcp` role: stateful addresses in `IA_NA`, relayed and direct clients, the DNS and NTP options, the client FQDN of RFC 4704, DUID reservations from IPAM and the client link-layer address of RFC 6939 for the correlation with the client's DHCPv4 lease (DHCP-09, DHCP-11, DHCP-13). It runs on the same configuration image, the same store and the same lease rules as DHCPv4: a DHCPv6 scope is an IPAM prefix with a DHCP policy, a lease is a row committed before the REPLY, and the role never reads the store while it answers. WP9.2 adds prefix delegation (`IA_PD`, sections 19.10 and 19.11) and the router advertisement check of DHCP-10 (section 19.12); temporary addresses (`IA_TA`) are not served. This section is for operators who serve IPv6 clients and for reviewers of `tenko_dhcp::v6`; the RFCs and their status are in [CONFORMANCE.md](CONFORMANCE.md).

### 19.1 The codec

`tenko_dhcp::v6` reads and writes DHCPv6 messages without allocating, in the manner of the DHCPv4 codec (section 1):

- **The view.** `Message::parse` checks the header of the message's type: the type and the three-octet transaction id of a client or server message, the type, the hop count, the link address and the peer address of a RELAY-FORW or RELAY-REPL (RFC 8415 sections 8 and 9). The options are walked when asked for; a malformed option ends the walk of its area there, the options before it stay readable, and `validate()` walks every option.
- **Nested options.** An `IA_NA` holds its IA Address options and a status, an IA Address its own status, a relay message the message it relays; `IaNa::addresses`, `IaAddress::status` and `Message::relay_message` read them from the same buffer.
- **The relay chain.** `RelayChain::parse` walks a RELAY-FORW inwards to the client's message, at most eight relays deep (`HOP_COUNT_LIMIT`, RFC 8415 section 7.6); a deeper chain or a RELAY-FORW without a Relay Message option is refused. The chain gives the link address of the innermost relay that sends one (a lightweight relay of RFC 6221 sends zero and the relay above it names the link), and the Interface-Id, the Remote-Id (RFC 4649) and the Client Link-Layer Address (RFC 6939) of the innermost relay that sends each.
- **The typed options.** DUIDs of the four types (DUID-LLT, DUID-EN, DUID-LL and DUID-UUID of RFC 6355, with their link-layer address, time, enterprise number or UUID), `IA_NA` and IA Address, `IA_PD` and IA Prefix (written with `begin_ia_pd` and `ia_prefix`, WP9.2), Status Code, the Option Request, Elapsed Time, Rapid Commit, Reconfigure Accept, the Client FQDN of RFC 4704, the Client Link-Layer Address of RFC 6939, the address lists of options 22, 23 and 31, the domain list of option 24 (uncompressed, RFC 3646 section 4), the NTP Server option of RFC 5908 with its sub-options, Remote-Id, User Class and Vendor Class.
- **The builder.** `MessageBuilder` writes the header and the options into a caller's buffer; an option that holds options is opened with `begin` and closed with `end`, which writes its length, so a RELAY-REPL around a RELAY-REPL around a REPLY with its `IA_NA`s is written outside in, in one pass. An option that does not fit returns `EncodeError::NoRoom` and leaves the message as it was; `rewind` takes back an opened option.
- **The flags of option 39.** RFC 4704 has the flags S (0x01), O (0x02) and N (0x04); option 81 of DHCPv4 has S, O, E (0x04) and N (0x08). `ClientFqdn::flags_v4` maps the DHCPv6 flags into the DHCPv4 layout, with E set since the name is always in the wire encoding, so the lease row and the DDNS rules read them one way.

The tests are `crates/tenko-dhcp/tests/dhcp6_codec.rs` (the fixtures in `fixtures/v6/`, annotated hex written from the RFC formats: SOLICITs as ISC dhclient and systemd-networkd send them, a REQUEST, RENEW, REBIND, RELEASE, DECLINE, CONFIRM and INFORMATION-REQUEST, relay chains one and two deep, a REPLY with the DNS and NTP options, a RELAY-REPL chain, and the malformed cases; every fixture written again through the builder octet for octet; loops over truncations, flips and random input), `tests/dhcp6_differential.rs` (the fixtures against `dhcproto`'s DHCPv6 decoder) and `tests/alloc6.rs` (no allocation from the parse to the hand-off of the change). The fuzz targets are `dhcp6_wire` (the whole message, the relay chain, every typed option, the domain list and the NTP option encoded again, and a REPLY built for every message that parses, which must read back) and `dhcp6_relay` (relay chains up to seven deep built from the input, their link address, Interface-Id and link-layer address, and the RELAY-REPL chain back with the Interface-Ids echoed), with seeds in `fuzz/seeds/`, in the weekly fuzz smoke (E31).

### 19.2 Scopes, pools and options

A DHCPv6 scope is a scope (section 3) on an IPAM prefix of role network that is IPv6: `POST /dhcp/scopes` names the prefix as for DHCPv4. Its pools are the prefix's IPAM ranges of role `dhcp_pool`, its exclusions the same as section 2 says (the explicit ones, the `reserved` and `infrastructure` ranges, the addresses of hosts that are not `dynamic`), plus the network's first address, the Subnet-Router anycast address (RFC 4291 section 2.6.1). The lease times are the valid lifetime: the pool's settings, else the range's `lease_secs`, else the scope's, else the server's. A scope on an IPv6 prefix also takes `v6` (refused on an IPv4 prefix, `dhcp.scope.invalid`):

| Field | Default | Meaning |
|---|---|---|
| `preferred_secs` | five eighths of the valid lifetime | The preferred lifetime, never above the valid lifetime |
| `rapid_commit` | true | Whether a SOLICIT with Rapid Commit gets a committed REPLY (RFC 8415 section 18.3.1) |
| `interface_id` | none | The relay Interface-Id (option 18, as text) that selects the scope before its link address does |

T1 and T2 are half and four fifths of the preferred lifetime (RFC 8415 section 21.4), or the scope's `t1_secs` and `t2_secs` scaled as in DHCPv4, and never above the preferred lifetime. `PATCH /dhcp/scopes/{prefix}` replaces `v6` whole, and `clear_v6` drops it; every scope item says its `family` (`v4` or `v6`).

The options of a DHCPv6 client are the values of space `dhcp6` in the same option sets (section 4): the server's, the shared network's and the scope's merged per code, the pool's, the reservation's. The built-in catalog (`tenko_core::dhcp::CATALOG_V6`) has, with Kea's names, 21 `sip-server-dns`, 22 `sip-server-addr`, 23 `dns-servers`, 24 `domain-search`, 27 and 28 the NIS servers, 29 and 30 the NIS domain names, 31 `sntp-servers`, 32 `information-refresh-time`, 41 and 42 the time zones, 56 `ntp-server`, 59 `bootfile-url`, 60 `bootfile-param`, 64 `aftr-name`, 82 `sol-max-rt` and 83 `inf-max-rt`. Option 56 holds the time servers' addresses in the option set; the server writes each as an `NTP_SUBOPTION_SRV_ADDR` sub-option (RFC 5908 section 4.1). The codes the server writes itself (`SERVER_MANAGED_V6`: the identifiers, the IAs and their addresses and prefixes, the option request, preference, elapsed time, relay message, authentication, server unicast, status code, rapid commit, Interface-Id, the reconfigure options, Remote-Id, client FQDN and client link-layer address) are refused in an option set, and a custom definition of a catalog code in `dhcp6` too.

Classes and policies (section 16) are DHCPv4 only. The MAC filters (section 6) hold for DHCPv6 clients by their link-layer address (19.4), and a restricted scope serves only clients an allow entry matches and clients with a reservation.

### 19.3 Reservations

A reservation of a DHCPv6 address is an IPv6 address of status `active` or `planned` of an interface of a `reserved` host inside a served DHCPv6 scope, as for DHCPv4 (section 12.1). It is keyed by the interface's DUID (IPAM's `Interface::duid`) when it has one, else by its MAC address, which the engine matches against the client's link-layer address; an interface with neither gives the IPAM-18 warning `no_identity`, and two reservations of one address or one key in a scope keep the first and report the second (IPAM-23). The reservation wins over the pool, its address is never offered to another client, and its options are the interface's option set. Its findings are the image's own (`Built::warnings6`), apart from the DHCPv4 ones.

### 19.4 The engine

`tenko_dhcp::v6::engine::handle` is a pure function of the image, the DHCPv6 lease table, the offers held, the request and the clock, as section 9 describes for DHCPv4:

- **The client.** Its DUID (option 1), which every message but an INFORMATION-REQUEST must carry; the IAID of each IA with the DUID is the identity of a binding. Its link-layer address comes from the Client Link-Layer Address option the relay on its link added (RFC 6939), else from its DUID-LLT or DUID-LL; a client with a DUID-EN or DUID-UUID behind a relay without RFC 6939 has none. The deny list drops a client whose MAC address it matches (DHCP-08).
- **The Server Identifier** (RFC 8415 section 16). SOLICIT, CONFIRM and REBIND must not carry one; REQUEST, RENEW, RELEASE and DECLINE must carry this server's; an INFORMATION-REQUEST may carry this server's. Any other message is ignored (`other_server` or `incomplete`). The server's DUID is `[dhcp.v6] server_duid`, else a DUID-UUID derived from the node identifier, which stays the same across restarts and differs between nodes.
- **The scope.** The relay's Interface-Id when a scope names it (the innermost relay that sends one first), else the link address of the innermost relay with one (RFC 6221), else, for a client on the listener's link, the listener's address. A scope of a shared network brings its siblings into the choice.
- **The address of an IA.** The client's reservation, its bound lease of the IA, an address it put in the IA when that one is free, then the pool: the walk starts where the hash of the IAID and the DUID points and looks at no more than 4,096 addresses from there, which in a pool of 2^64 addresses finds a free one at once. Free means inside a pool and not excluded, not another client's reservation, binding or offer, not an abandoned address (offered to nobody, the decliner included, until its hold ends), and not given to another IA of the same message.

| Request | Answer | Written |
|---|---|---|
| SOLICIT | ADVERTISE with an address per `IA_NA`, `NoAddrsAvail` for an IA without one; when no IA gets one, an ADVERTISE with the identifiers and a top-level `NoAddrsAvail` only (RFC 8415 section 18.3.9) | Nothing; the addresses are held for `[dhcp] offer_secs` |
| SOLICIT with Rapid Commit, where the scope allows it | REPLY with Rapid Commit after the commit | The bindings (`granted`, or `renewed` for the client's own) |
| REQUEST | REPLY after the commit; an IA without an address gets `NoAddrsAvail` | `granted` or `renewed` |
| RENEW | REPLY after the commit with the binding's new lifetimes; an address of the IA that is not the client's binding or not on the link comes back with lifetimes of zero (RFC 8415 section 18.3.4); an IA without addresses and without a binding gets `NoBinding` | `renewed`, or `granted` for a lost binding taken back |
| REBIND | As RENEW, without a Server Identifier | `rebound` or `granted` |
| CONFIRM | REPLY with `Success` when every address of its IAs is on the link, else `NotOnLink`; no reply without an address (RFC 8415 section 18.3.3) | Nothing |
| RELEASE | REPLY with `Success` after the commit; an IA the client holds nothing of gets `NoBinding` | `released`, ending now |
| DECLINE | As RELEASE | The address `abandoned` for `[dhcp.decline] hold_secs` |
| INFORMATION-REQUEST | REPLY with the options; one that carries an IA is ignored | Nothing |
| ADVERTISE, REPLY, RECONFIGURE, RELAY-REPL, other types | Ignored | Nothing |

A message changes at most eight bindings, its first eight IAs; the change of one message is one commit. The reply carries the server's DUID, the client's, the `IA_NA`s in the client's order with their addresses and the T1 and T2 of the first address's lifetimes, a status where the table says, Rapid Commit, the Client FQDN (19.6), and the options the client asks for in its Option Request in its order from the most specific level that holds them, with 23 and 24 also when the client does not ask for them; an option that does not fit within 1,452 octets is left out whole. Through relays the reply is a RELAY-REPL per RELAY-FORW from the outermost in, each with the hop count, the link address and the peer address of its RELAY-FORW and its Interface-Id echoed (RFC 8415 section 19.3), sent to the address the outermost RELAY-FORW came from on `[dhcp.v6] relay_port` (547); a client on the listener's link gets the reply at its link-local address on `[dhcp.v6] client_port` (546).

While the store refuses lease writes (P3-Q14), a REQUEST, RENEW or REBIND of a binding the client holds is answered with the time the binding has left and nothing is written, a SOLICIT is answered only for a client with a bound lease, and everything else is dropped as `store_refused`. A client that sends to the server's unicast address without the Server Unicast option is served, not answered with `UseMulticast`: the listener does not learn whether a datagram was multicast (no `IPV6_PKTINFO`, as `IP_PKTINFO` in section 10.3), and in relay mode every request arrives unicast from the relay.

The tests are `crates/tenko-dhcp/tests/engine6.rs` (every message type, the lifetimes and T1 and T2, rapid commit allowed and refused, relay chains two deep with a lightweight relay, the Interface-Id selection, reservations by DUID and by MAC through RFC 6939, the filters, the Server Identifier rules, two IAs in one commit, the options 23, 24 and 56, option 39, the store refusal), `tests/engine6_server.rs` (a relay on loopback), `tests/image6.rs` (the image of the rows) and `tests/role6.rs` (the role with both families over the in-memory store).

### 19.5 Leases

A DHCPv6 lease is a row of `dhcp.leases6`, keyed by VRF and address (`tenko_core::dhcp::Lease6`): the address and its prefix length (128 for an address, the delegated length for a prefix keyed by its first address), `na` or `pd` (section 19.11), the scope, the IAID and the DUID, the link-layer address and its type, the binding state, the client's last transaction time, the ends of the valid and preferred lifetimes, the name of RFC 4704 and its flags (in the layout of option 81), the relay closest to the client (link address, peer address, hops, Interface-Id, Remote-Id), the observation time and the DDNS outcome. Each event is a row of `dhcp.history6` (key time, VRF, address), purged by the retention of section 8.5 with `dhcp.history`. Both tables are additive in data format 4; there is no `by_client` table, the role derives its client index from the rows.

The lease path is the one of section 8 for the other table: the engine's change (`PendingChange6`, every field inline) goes to `StoreLeases6`, whose committer builds one batch per change (a row and a history row per binding, and the IPAM facts), proposes the batches concurrently with the changes that touch the same address or client one after another, applies a committed batch to the role's DHCPv6 table and only then completes the ticket; the worker sends the REPLY then. The DHCPv6 store shares the refusal gate of the DHCPv4 store, so one refusal closes both and one commit opens both. The leader service `dhcp.expiry6` writes the bindings past their valid lifetime and the abandoned addresses past their hold as `expired`, in batches under the leader fence, as `dhcp.expiry` does.

The lease batch carries the IPAM facts of the source `dhcp:<node>` (section 12.3): the address fact of the IPv6 address with the client's MAC address from its link-layer address, and the name fact of RFC 4704. A device whose DHCPv4 lease and DHCPv6 lease name one MAC address shows both addresses in IPAM under that MAC (`GET /observations?mac=`), which is the correlation of DHCP-11; a client without a link-layer address (a DUID-EN behind a relay without RFC 6939) is not correlated.

### 19.6 DDNS

DHCPv6 leases take the path of section 13 through the same worker, `dhcp.ddns`, which follows `dhcp.leases6` beside `dhcp.leases`. A DHCPv6 lease with a name writes an AAAA record where a DHCPv4 lease writes an A record, a DHCID of identifier type 2 (the DUID, RFC 4701 section 3.3) at the forward name, and the PTR under `ip6.arpa` in the most specific reverse zone Tenko serves for the address. The name is the one of option 39 (RFC 4704), under the scope's forward zone; a DHCPv6 scope that names no forward zone takes the zone of the first name of its option 24. The reply's option 39 carries the flags of section 13.3 in the RFC 4704 layout: S when the server writes the AAAA record, none of S, O and N when the client writes it, N when DDNS is off. A client whose DHCPv4 identity is the RFC 4361 form of the same IAID and DUID gets the same DHCID for both families and holds one name with an A and an AAAA record; the DHCID goes with the last address record of either family. A dual-stack client whose DHCPv4 client identifier is its MAC address has another DHCID for each family, and name protection gives the name to whichever writes it first (RFC 4703 section 5.4 recommends RFC 4361 identifiers for dual-stack clients).

### 19.7 The listeners and the role

A `[dhcp] listen` entry with an IPv6 address is a DHCPv6 listener on `[dhcp.v6] port` (547):

| Mode | Linux | Windows |
|---|---|---|
| `relay` | Binds the unicast address on port 547: relay agents send their RELAY-FORW there. One `SO_REUSEPORT` socket per worker | The unicast address; one socket shared by the workers |
| `direct` | Binds `[::]:547` with `SO_BINDTODEVICE` to the entry's interface and joins `All_DHCP_Relay_Agents_and_Servers` (`ff02::1:2`) on it; the entry's address selects the scope of the link. One socket the workers share, since a multicast reaches every socket of a reuse-port group | Binds `[::]:547` and joins `ff02::1:2` on the system's default interface |

| Key | Default | Meaning |
|---|---|---|
| `[dhcp.v6] port` | 547 | The DHCPv6 server port |
| `[dhcp.v6] relay_port`, `client_port` | 547, 546 | Where replies to relay agents and to clients go |
| `[dhcp.v6] server_duid` | a DUID-UUID of the node | The server's DUID in hexadecimal, 3 to 130 octets |

`[dhcp] workers`, `offer_secs` and `[dhcp.decline] hold_secs` apply to both families. Port 547 is below 1024 like 67 and needs nothing more than `CAP_NET_BIND_SERVICE` in relay mode; direct mode needs the drop-in of section 10.4 for `SO_BINDTODEVICE`.

The role starts the DHCPv6 server after the DHCPv4 one, over the same image (a change of the configuration swaps the image of both, a snapshot install both tables with the images), and stops it with the DHCPv4 one. The ready line lists the DHCPv6 listeners. `GET /nodes/{id}/dhcp` reports the role; its report (`DhcpStatus`) holds `listeners6`, `scopes6` and `leases6` beside the DHCPv4 figures, and `serving` counts the listeners of both families; the API's answer carries the three as `listeners6`, `scopes6` and `leases6`, and (WP9.4) the router advertisement check as `ra` (section 19.12) and the DHCPv6 server's DUID in hexadecimal as `server_duid`. The metrics: `tenko_dhcp_packets_total{family="v6",type,outcome}` with the types `solicit`, `request`, `confirm`, `renew`, `rebind`, `release`, `decline`, `information-request` and `other`; `tenko_dhcp_leases{state}` counts the rows of both tables; `tenko_dhcp_dropped_total`, `tenko_dhcp_declines_total`, `tenko_dhcp_commit_duration_seconds` and `tenko_dhcp_exchange_duration_seconds` (`offer`: SOLICIT to ADVERTISE; `ack`: to a committed REPLY) count both families.

### 19.8 What the API and the UI show

The routes of section 7 read and write DHCPv6 scopes, pools (IPAM ranges, delegation pools among them: `GET /dhcp/pools` lists a `dhcp_pd_pool` range with its size in prefixes), exclusions and `dhcp6` option sets. The lease, history and utilization routes read the DHCPv4 tables only: a DHCPv6 scope's utilization reads zero, and the DHCPv6 leases are in the store, in the role's report counts, in the metrics and as IPAM observations. WP9.4 adds the DHCPv6 leases and history to the routes and the UI, the `v6` settings and the DHCPv6 catalog to the scope page and the option editor, and the DUID reservations to the host page. WP9.4 completes the read side for both families:

| Route | DHCPv6 |
|---|---|
| `GET /dhcp/leases`, `GET /nodes/{id}/dhcp/leases` | The DHCPv4 leases in address order, then the DHCPv6 leases of `dhcp.leases6`; each item says its `family`. A DHCPv6 item has `kind` (`na`; `pd` with WP9.2), `prefix_len`, `iaid`, `duid`, `link_layer`, `preferred_ends` and `relay6`, a DHCPv4 item its `client`; both have `mac` where the client's MAC address is known and `peer`, the client's lease of the other family with the same MAC address (an active one first, else the one that ends last: the correlation of DHCP-11). Filters `family` (`v4`, `v6`) and `duid` (hexadecimal) beside the others; `addr` matches the text of either family. Each family keeps its own cursor position: a page that ends in the DHCPv4 leases goes on there, and the DHCPv6 part starts once they are read |
| `GET /dhcp/leases/{addr}`, `POST /dhcp/leases/{addr}/release`, `POST /nodes/{id}/dhcp/leases/{addr}/release` | The address is either family; a DHCPv6 lease is released by the node command `dhcp.lease6.release` (the row `released`, a history row `reclaimed`, the IPAM facts expired in the same batch), audited as `dhcp.lease.release` as a DHCPv4 release is |
| `GET /dhcp/history`, `GET /nodes/{id}/dhcp/history` | `dhcp.history` and `dhcp.history6` merged newest first by the node command `dhcp.history.read`; a row of one table is answered only when no unread row of the other can be newer, so the order holds across pages. A DHCPv6 row has `duid`, `iaid` and `prefix_len`, and `mac` when the DUID is a DUID-LLT or DUID-LL (and, since WP9.4, the RFC 6939 address the row keeps). Filters `family`, `duid`, and `addr` of either family |
| `GET /dhcp/scopes/{prefix}/utilization` | A DHCPv6 scope counts its DHCPv6 leases over its pools (the Subnet-Router anycast address and the exclusions taken out); `family` says which, `pool_size` and `free` stop at 2^64 - 1, and `pool_bits` gives a pool of 2^32 addresses or more as a power of two. The scope items' `leases` count the active DHCPv6 leases of a DHCPv6 scope |
| `GET /nodes/{id}/dhcp` | `listeners6`, `scopes6` and `leases6` beside the DHCPv4 figures; `ra` and `server_duid` (WP9.4) |
| `GET /dhcp/leases` (WP9.4, `IA_PD`) | `kind` (`na`, `pd`) keeps one kind of DHCPv6 lease and leaves the DHCPv4 part out; `addr` that is an IPv6 address or prefix (`2001:db8:180::/48`, host bits ignored) also finds the DHCPv6 leases whose address or delegated prefix lies inside it and the delegated prefixes that hold it; a `pd` item has `address_lease`, the address lease (`na`) of the same DUID in the same VRF, active first |
| `GET /dhcp/history` (WP9.4) | A DHCPv6 row keeps the client's link-layer address (`Lease6Event::link_layer`, a serde default: a row written before reads as none), so `mac` names and the `mac` filter finds a client with a DUID-EN or DUID-UUID behind an RFC 6939 relay |
| `GET /dhcp/pools`, `GET /dhcp/scopes/{prefix}/utilization` (WP9.4) | Section 19.10 |
| `GET /dhcp/option-catalog` | Both spaces, `dhcp4` first, each by code: the DHCPv6 catalog and the server-managed DHCPv6 codes with Kea's names; `space` keeps one, another value answers 400 `sys.invalid_query`. An option set's `dhcp6` values are named by the catalog and typed as it says |

Every page read stays one node command row and one audit record `dhcp.lease.read`, with the new filters (`family`, `exact6`, `addr6`, `duid`) in its context. `tenko dhcp lease list` and `tenko dhcp history` take `--family v4|v6` and `--duid HEX` (and, WP9.4, `tenko dhcp lease list` takes `--kind na|pd`) and show the family and the MAC address; `lease show` and `lease release` take an IPv6 address. The tests are `crates/tenko-api/tests/dhcp_leases.rs` (both families through the routes over a role on the in-memory store: the correlation, the filters, the cursors across the two parts, the merged history and its pages, the utilization of a DHCPv6 scope and of a /64 pool, the node report, the release and its audit, the catalog and a typed `dhcp6` option set) and `crates/tenko-dhcp/tests/history_both.rs` (pages of every size over interleaved rows of both tables). Section 7 says what the UI shows.

### 19.9 The lab round `dhcp6`

`ROUNDS=dhcp6 bash deploy/compose/lab-dhcp/smoke.sh` runs E29's IA_NA, relay and correlation rows on a dual-stack topology of its own (`compose.dhcp6.yml`, `dhcp6.sh`; the lab's README has the commands): ISC's `dhcrelay -6` and `-4` relay the links `lan6` (`2001:db8:101::/64`) and `iot6` (`2001:db8:102::/64`) to the node's `2001:db8:100::10` and `192.0.2.10`; the clients are ISC's `dhclient -6` with a DUID-LL, systemd-networkd run on its own with Rapid Commit, and `relay-test6.py`, a relay agent written against RFC 8415 that sends chains two deep with a lightweight relay, the Client Link-Layer Address of RFC 6939 and option 39.

| Row | Checks |
|---|---|
| `v6.lease.dhclient` | dhclient -6 on lan6 gets an address of the pool through dhcrelay, with options 23, 24 and 56 |
| `v6.lease.iot` | dhclient -6 on iot6 gets an address of the iot6 pool: the relay's link address selects the scope |
| `v6.lease.networkd` | systemd-networkd gets an address of the pool with the DNS and NTP servers |
| `v6.rapid-commit` | networkd's SOLICIT is answered with a committed REPLY and no REQUEST follows |
| `v6.renew` | dhclient renews at T1 and keeps its address |
| `v6.interface-id` | a chain two deep whose outer link has no scope gets an address of the scope its Interface-Id names, the Interface-Id echoed |
| `v6.reservation` | an IPAM host of mode `reserved` with dhclient's DUID gets its reserved address |
| `v6.correlation.rfc6939`, `v6.correlation.duid` | the DHCPv4 and the DHCPv6 lease of one MAC address are both IPAM facts of that MAC, by RFC 6939 and by DUID-LL |
| `v6.fqdn` | option 39 gives the AAAA, the DHCID and the `ip6.arpa` PTR in Tenko's zones, of origin `dhcp` |
| `v6.release` | a RELEASE is answered and removes the names |
| `v6.pd` | dhclient -6 -P on lan6 gets a /60 of the delegation pool `2001:db8:180:100::/56` (the scope of `2001:db8:180::/48`, in lan6's shared network) through dhcrelay, and IPAM holds it as a `network` fact of source `dhcp:<node>` (WP9.2) |
| `v6.pd.release` | dhclient -6 -P -r: a RELEASE is answered and the fact of the prefix ends |
| `v6.ra.flags_off` | radvd on servers6, the node's own link, with M and O off and a scope on `2001:db8:100::/64`: the health view has `dhcp.ra.flags_off` naming the scope |
| `v6.ra.managed` | radvd with M on: the finding is gone and no other `dhcp.ra.*` finding names the link |
| `v6.ra.without_scope` | the scope disabled while M stays on: the health view has `dhcp.ra.managed_without_scope` |

For the RA rows the node runs the roles controller, dhcp and probe from `probe.Dockerfile`'s image: the binary of the Tenko image, the same bytes, with the file capability `cap_net_raw+ep` (Docker gives a container's non-root user no effective capability, so the lab does what `deploy/systemd/probe.conf` says for a system without systemd), `NET_RAW` in the container's bounding set and `no-new-privileges` off for that one container.

### 19.10 Delegation pools

A delegation pool (WP9.2, RFC 8415 section 6.3) is an IPAM range of role `dhcp_pd_pool` with a `delegated_len`: the length of the prefixes it hands to requesting routers. It is made and changed through the IPAM range routes (`POST /prefixes/{id}/ranges`, `PATCH /ranges/{id}`), like an address pool, and IPAM checks it there (`ipam.validation`, field `delegated_len` unless noted):

| Rule | Why |
|---|---|
| The range belongs to an IPv6 network (field `role` otherwise) | Ranges belong to networks (IPAM-02, `ipam.range.not_in_network`); delegation is DHCPv6 only |
| `delegated_len` is set, longer than the network's length and at most 64 | A pool hands out parts of its network; a /64 is one link (RFC 4291 section 2.5.1), and a /65 or longer prefix cannot carry SLAAC |
| The range starts on a boundary of `delegated_len` and ends at the last address of a prefix | Every delegated prefix is a whole prefix of the pool; the pool of a whole CIDR is the simple case |
| No overlap with another range of the network (`ipam.range.overlap`), no reservation inside it (`ipam.range.covers_reservation`) | The same rules as an address pool, so a delegated prefix never holds a pool's address or a reserved one |
| `delegated_len` on any other role is refused | A length means nothing for an address pool |

**What the API and the UI show** (WP9.4). `GET /dhcp/pools` lists a delegation pool with `role` `dhcp_pd_pool` and its `delegated_len` beside the address pools (`role` `dhcp_pool`); its `size` is the number of prefixes it may delegate, the prefixes an excluded address lies in taken out (`Scope6Image::delegable`, which a property test holds to the engine's `is_delegable`), and `leased` the active `pd` rows of the scope that are prefixes of the pool. The utilization of a DHCPv6 scope with delegation pools has a `pd` block with `pools`, `pool_size`, `leased`, `free` and `utilization` in prefixes; the address figures leave the delegated prefixes out. Section 7 says what the UI shows.

An address of IPAM inside a delegation pool is warned about (`ipam.address.in_range`) and its prefix is not delegated while the address is there; the scope's exclusions and its `reserved` and `infrastructure` ranges keep the prefixes they touch out the same way. The pool's settings (`PUT /dhcp/pools/{range}`: the lease times; its classes are kept and, like every class, DHCPv4 only) and its option set (owner `pool:<range>`) are those of an address pool, and its lease times give the valid lifetime of a prefix in the order of section 19.2.

**Where a pool is reached.** The pool serves the scope of its network and every scope of that scope's shared network. A link whose scope is a /64 therefore reaches a delegation network of its own (for example a /48 network with a scope and a pool, and no address pool) by putting both scopes in one shared network; a scope on a shorter network can hold its address pool and its delegation pool side by side. The scope that holds the pool is the binding's scope (`Lease6::scope`) and gives the DDNS settings (none apply to a prefix) and the options of the reply when no address was granted.

**Why a range.** The plan named a table `dhcp.pd_pools`. A range is the IPAM object for a part of a network that a service hands out: the IPAM tree, the overlap and reservation rules, the range routes, the pool settings and option sets of `dhcp.pools` and the Kea export's pool walk all take it as it is, and the UI shows it where the operator plans the space. A separate table would have needed its own routes, its own overlap rules against IPAM and its own place in the tree. The delegated length is a property of the pool's shape, so it lives on the range (`Range::delegated_len`, a serde default: a stored range without it reads as none) rather than in `dhcp.pools`, where a range without settings would have had no length.

Changing the delegated length of a pool with live bindings is allowed: a binding of the old length is no longer a prefix of the pool, so a renewal gets it back with lifetimes of zero and a prefix of the new length, and until the old bindings end the allocator does not see a new prefix that only overlaps an old one (it checks the prefix's first address). Change the length of a pool without bindings, or shrink the lifetimes first.

### 19.11 Prefix delegation in the engine

The engine reads the `IA_PD`s of a message after its `IA_NA`s; both share the eight bindings of a message (`MAX_BINDINGS`), and an IA past that is not answered. The prefix of an `IA_PD` (`alloc::pick_pd`) is the client's bound prefix of that IA, a prefix it put in the IA (an IA Prefix) when that one is a free prefix of a pool, then a walk over the pools that starts where the hash of the IAID and the DUID points and looks at no more than 4,096 prefixes per pool, the pools of a hinted length first (an IA Prefix of `::` with a length is a hint of the length only, RFC 8415 section 18.3.9). Free means: a prefix of a pool and not excluded, no other client's binding, no binding of an address, no abandoned row and no other client's offer at its first address, and not given to another IA of the message. There are no reservations of a delegated prefix: IPAM holds no intent that ties a prefix to an interface, so a router that must keep its prefix keeps it by renewing; a reservation of a prefix needs that intent first.

| Request | `IA_PD` answer | Written |
|---|---|---|
| SOLICIT | ADVERTISE with an IA Prefix per `IA_PD`, `NoPrefixAvail` inside an `IA_PD` without one; when no IA of a message with an `IA_PD` gets anything, an ADVERTISE with every IA and its status (RFC 8415 section 18.3.9) | Nothing; the prefixes are held for `[dhcp] offer_secs` |
| SOLICIT with Rapid Commit | REPLY after the commit | `granted` or `renewed`, kind `pd` |
| REQUEST | REPLY after the commit; `NoPrefixAvail` for an `IA_PD` without a prefix | `granted` or `renewed` |
| RENEW, REBIND | The binding's new lifetimes; a prefix of the IA that is not the client's binding comes back with lifetimes of zero (RFC 8415 section 18.3.4); an `IA_PD` with no prefix that cannot be served gets `NoBinding` | `renewed` or `rebound`, `granted` for a new one |
| RELEASE | `NoBinding` for an `IA_PD` the client holds nothing of | `released`, ending now |
| DECLINE, CONFIRM | The `IA_PD`s are left alone: both concern addresses (RFC 8415 sections 18.3.3 and 18.3.8) | Nothing for the prefixes |

A delegated prefix's lifetimes are the valid lifetime of the pool's lease times and the preferred lifetime and T1 and T2 of the scope that holds the pool (section 19.2); the `IA_PD` carries them as an `IA_NA` does. While the store refuses lease writes, a RENEW or REBIND of a bound prefix is answered for the time it has left and nothing is written, as for an address. The name of option 39 goes with an address: a message with `IA_PD`s only writes no name and answers no option 39.

**The binding.** A delegated prefix is a row of `dhcp.leases6` of kind `pd`, keyed by its VRF and its first address, with `prefix_len` the delegated length; its history rows, its commit before the REPLY through `StoreLeases6`, the refusal gate and `dhcp.expiry6` are those of an address. The role's client index is kept per kind (`Lease6Table::by_client(scope, kind, identity)`): RFC 8415 section 12 makes an IAID unique among the IAs of one type only, so a router's `IA_NA` and `IA_PD` may share IAID 1, and one never finds the other. The store refuses a change that would give one kind's row to the other.

**What IPAM shows.** The lease batch writes, for a bound prefix, the fact `Observed::Network` of source `dhcp:<node>` with the prefix as its subnet, named `delegated to <MAC>` (or `delegated to DUID <hex>` without a link-layer address), under the subject `network:dhcp-pd/<vrf>/<prefix>/<len>`; it ends when the binding ends and at once on a release. An address fact would have told the reconciler that the prefix's first address is in use by the router's MAC, which it is not, and its rules would have proposed a host for it; the reconciler reads network facts of network controllers only, so the delegation stays an observation under the delegation network in `GET /observations?type=network` and opens no proposal. The DDNS worker leaves rows of kind `pd` alone.

### 19.12 The router advertisement check (DHCP-10)

IPv6 hosts learn from the router advertisements of their link (RFC 4861 section 4.2) whether to ask DHCPv6 at all: the M flag (managed address configuration) for addresses, the O flag (other configuration) for the other options only. A DHCPv6 scope on a link whose routers set neither serves nobody, and a router that sets M on a link without a scope sends its hosts to a server that does not answer. **DHCPv6 never sets a default route:** the default route comes from the advertisements' router lifetime, so a host needs the advertisements even when DHCPv6 gives its address; Tenko has no option for a route and sends none.

**What runs.** With a `probe` role in the process the `dhcp` role starts `tenko_dhcp::ra::run`: a raw ICMPv6 socket (`tenko_scan::ra::RaSocket`, Linux) hears every advertisement the host receives, with the interface it came in on, and a Router Solicitation on every link with an IPv6 address at the start and every ten minutes asks the routers to answer at once. The socket needs `CAP_NET_RAW`, which `deploy/systemd/probe.conf` grants with the probe role (as for ARP); an unprivileged ICMPv6 datagram socket receives echo replies only and cannot replace it. Without the capability the role says so once in its log, the check is `unavailable`, and while DHCPv6 scopes exist the health view shows `dhcp.ra.unchecked`. No other capability is used, and without a probe role the check is `off` and shows nothing. On Windows the check is unavailable.

**What it keeps.** Per link and router the last advertisement's flags, router lifetime and prefixes (the prefix information options; prefixes shorter than /16 are left out), and the node's own IPv6 networks on the link; at most 16 routers per link and 1,024 in all, the oldest going first, so a host that sends advertisements from many addresses cannot grow it; a router not heard for an hour is forgotten (RFC 4861 allows at most 1,800 seconds between unsolicited advertisements). The parser (`tenko_scan::ra::RouterAdvert`) allocates nothing and refuses what RFC 4861 section 6.1.2 says a host discards: a message shorter than its fixed part, a code other than 0, an option of length zero or past the end, a source that is not link-local. It has the fuzz target `scan_ra`.

**What it finds.** A link's flags are those of any of its routers; its scopes are the enabled DHCPv6 scopes whose network overlaps a prefix its routers advertise or a network of the node's own addresses on it. The findings are health rows of `GET /system/status`, with the parameters `node`, `interface`, `routers` and `scopes` or `prefixes`:

| Code | When | Severity |
|---|---|---|
| `dhcp.ra.flags_off` | The link has a scope and its advertisements set neither M nor O | warning |
| `dhcp.ra.other_only` | O without M while a scope of the link has address pools: hosts ask for options only (stateless DHCPv6 may be meant) | info |
| `dhcp.ra.managed_without_scope` | M is set and no enabled scope covers the link | warning |
| `dhcp.ra.unchecked` | The socket cannot be opened (no `CAP_NET_RAW`, or not Linux) and DHCPv6 scopes exist | info |

The role's report carries the check's state (`off`, `unavailable`, `watching`), the links heard with their routers, flags, prefixes and scopes, and the findings (`DhcpStatus::ra`); `GET /nodes/{id}/dhcp` answers them as `ra` (`check`, `reason` when unavailable, `links` with `interface`, `routers`, `managed`, `other`, `prefixes`, `scopes` and `seen`, `findings` with `code`, `interface`, `detail` and `params`), and the UI shows them on the leases page and the health rows on the Nodes page (section 7). The check sees the links this node is on: a relayed link's advertisements reach a probe on that link, which in this phase is a probe in the same process as the `dhcp` role. A delegating router's own `IA_PD` request does not depend on the flags of its upstream link (RFC 7084 requests prefixes either way), so the check does not judge delegation pools.

The tests are `crates/tenko-scan/tests/ra.rs` (the fixtures in `tests/fixtures/ra/`: advertisements as radvd and home routers send them, with RDNSS, DNSSL, MTU and the source link-layer option, and the malformed cases; truncations and every octet flipped), `crates/tenko-dhcp/tests/ra.rs` (every finding and its counter-case, the limits and the forgetting of the watch, the report of a check that cannot run), `crates/tenko-api/tests/system_dhcp_ra.rs` (the health rows and their severities), `crates/tenko-dhcp/tests/engine6_pd.rs` (every message with `IA_PD`, hints, exhaustion, exclusions, shared networks, the store refusal), `tests/lease6_index.rs` (the client index per kind), `crates/tenko-ipam/tests/delegation.rs` (the range rules), the delegation pools of the reference image in `src/config/image_tests.rs`, and the network fact in `crates/tenko-ipam/src/observe/dhcp/tests.rs`; the lab rows of section 19.9.
