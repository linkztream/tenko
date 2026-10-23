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
| `GET /dhcp/option-catalog`; `/dhcp/option-defs`; `/dhcp/option-sets/{owner}` | the catalog, definitions, option sets |
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

The web UI's DHCP area (`/dhcp`) has the scope list with utilization, the scope page with its pools, exclusions, options and effective options, the shared networks, the options with the catalog and the custom definitions, the classes and policies, the MAC filters, and the DHCP section of the settings (`/settings/dhcp`). WP8.6 completes it: the scope page's DDNS tab (every field of the scope's DDNS settings, the server's settings it starts from and what the security profile does; a scope's own settings cannot be cleared back to the server's through the API, so the tab offers to copy the server's) and network boot tab (the boot server and file options 66, 67, 150 and 209 to 211, the scope's boot policies per client type and a dialog that adds one as a class, a policy and its option 67); the policy editor's four actions (options, range, lease time, DDNS) and an architecture picker for option 93 matches; the effective view that takes a client's MAC, client identifier, vendor class, user class, architecture and host name and says, per option, which level and which policy gave it; the lease list's live strip (the chosen scope's utilization, or a bar per scope, and the leases granted since the page was opened); the host page's DHCP reservations block (each address of a `reserved` host with the identity it is keyed by, the scope it falls in, whether the role serves it and its lease); and the first-run wizard's DHCP step (the first scope and the listener, written after setup, with the `[dhcp]` section on the result step).

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
| `[dhcp] listen` | none | Listeners: `{ address, mode = "relay" or "direct", interface }`, or an address alone for relay mode. Empty: the role builds its tables and answers nothing (the health row `dhcp.role.not_serving`) |
| `[dhcp] port` | 67 | The server port |
| `[dhcp] workers` | one per CPU, at most 8 | UDP workers per listener, 0 to 64 |
| `[dhcp] offer_secs` | 10 | How long an offer holds its address in memory, 1 to 300 |
| `[dhcp] relay_port`, `client_port` | 67, 68 | Where replies to relay agents and to clients go (tests and labs use other ports) |
| `[dhcp] proxy`, `proxy_port` | none, 4011 | Proxy DHCP listeners for boot clients (WP8.4, section 16.3): unicast IPv4 addresses, each listed once, not on `port` where `listen` holds the same address |
| `[dhcp.probe] timeout_ms`, `cache_secs` | 300, 600 | The conflict probe (WP8.5) |
| `[dhcp.decline] hold_secs` | 86,400 | How long a declined address stays abandoned |
| `[dhcp.ddns] retries`, `backoff_ms` | 5, 1,000 | The DDNS worker (WP8.3) |
| `[dhcp.history] days` | the installation's setting, else the profile's | A node-local retention of the lease history, 1 to 3,650 days |

`tenko config check` refuses an entry that is not a unicast IPv4 address, an interface on a relay listener, an address listed twice, and values outside the ranges above.

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

UDP 547 (DHCPv6) joins in Slice 9. The installer (`deploy/install.sh`) offers `controller,dhcp` and `controller,dns,dhcp`, checks that no other process holds UDP 67, and reminds that `[dhcp] listen` must be set. `deploy/README.md` has the walk-through.

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

WP9.3 writes Tenko's DHCPv4 configuration and leases in the form ISC Kea 2.6 reads (MIG-16, decisions P3-Q10 and P3-Q17 (a)), so that leaving Tenko is never blocked by a format only Tenko reads: `kea-dhcp4` starts from the export and keeps the clients' addresses. This section is for operators who leave Tenko or keep a Kea server as a fallback, and for reviewers of `tenko_dhcp::export::kea`. The DHCPv6 half (`Dhcp6`, `kea-dhcp6 -t`) comes with the DHCPv6 server (WP9.1).

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
| `kea-dhcp-ddns.json` | when a scope writes names: a `{"DhcpDdns": {..}}` skeleton for `kea-dhcp-ddns` |

The route is `GET /api/v1/dhcp/export?format=kea` (`leases=false` leaves the lease file out; `leases` is true when absent): `dhcp4`, `leases4_csv`, `dhcp_ddns` and `losses`. An unknown format answers 400 `dhcp.export.format`, a server without the DHCP configuration service 409 `dhcp.module.disabled`. The export is server-wide configuration and the leases are personal data: the caller needs `dhcp.read` on the `dhcp_scope` singleton (global roles only), and every export writes the audit record `dhcp.export` with the format, whether the leases were included, the number of scopes, lease rows and report entries. It reads every row at one revision; the listeners come from the `dhcp` role when it runs in the process.

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
| `export.kea.lease.scope` | Leases of scopes the export left out |

### 18.4 Verification

The unit tests in `crates/tenko-dhcp/src/export/kea/` cover the expressions, the options, the pools, the lab-shaped configuration with every level, class, policy and filter kind (including that every class a test, pool or subnet names is defined before it), the lease file and the report; `crates/tenko-api/tests/dhcp_export.rs` the route, its audit record and its errors; `crates/tenko/tests/acceptance_kea_export.rs` the command line through the binary. E30's DHCPv4 rows run in the compose lab (section 11, `deploy/compose/lab-dhcp`, profile `kea`, `kea.Dockerfile` with Kea 2.6 from Debian 13): after the other rows the smoke adds a policy with a DDNS action, exports with the leases, and checks:

| Row | Checks |
|---|---|
| `export.kea` | `kea-dhcp4 -t` accepts `kea-dhcp4.json` |
| `export.kea.report` | the report names the DDNS policy (`export.kea.policy.ddns`) |
| `export.kea.reservation` | with the node stopped, Kea on the node's address from the export gives client-lan its reservation `192.0.2.80` with options 3 and 6 |
| `export.kea.lease` | client-iot asks again (INIT-REBOOT) and keeps the address of its exported lease |
