# DHCP

This page describes how Tenko DDI configures DHCP, reads and writes DHCP messages and, as Phase 3 lands, how the `dhcp` role serves them. It is for operators who set up scopes, pools and options, for builders of the DHCP server, and for those who want to know what a node accepts on the wire. Section 1 describes the DHCPv4 wire codec in `crates/tenko-dhcp` (`tenko_dhcp::v4`); sections 2 to 7 the configuration: the model, scopes and pools, options and the catalog, classes and policies, MAC filters, and the API and command line (`tenko_dhcp::config` and the `/dhcp` routes). Where this page and the code differ, the code is right. The requirements are DHCP-01 to DHCP-08 and DHCP-13 in [REQUIREMENTS.md](REQUIREMENTS.md); the RFCs and their status are in [CONFORMANCE.md](CONFORMANCE.md); the contracts every Phase 3 package builds on are in [dhcp-contracts.md](dhcp-contracts.md).

Contents:

1. [The wire format](#1-the-wire-format)
8. [Leases](#8-leases)
9. [The engine](#9-the-engine)
2. [The model](#2-the-model)
3. [Scopes and pools](#3-scopes-and-pools)
4. [Options and the catalog](#4-options-and-the-catalog)
5. [Classes and policies](#5-classes-and-policies)
6. [MAC filters](#6-mac-filters)
7. [The API and the command line](#7-the-api-and-the-command-line)

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

Options are set per owner: `server`, `shared_network:<id>`, `scope:<prefix>`, `pool:<range>`, `policy:<id>` and `host:<interface>` (a reservation's options, on the IPAM interface). `PUT /dhcp/option-sets/{owner}` replaces the whole set; each value is given in wire form (`data`, hexadecimal) or typed (`typed`, for example `{"ipv4": {"values": ["192.0.2.53"]}}`, `{"text": "example.test"}`, `{"unsigned": [1500]}`, `{"names": ["example.test"]}`) and stored in wire form after it has been checked against the type of its code: `dhcp.option.unknown` for a code without a type, `dhcp.option.invalid` for data that does not fit or a code given twice. An owner without options reads as an empty set at revision 0. Every value reads back with its name and its typed view.

The options a client gets merge the levels from the least to the most specific, the later level winning per code in the order the codes first appear: the server, the scope's shared network, the scope, the policies that match the client (the first in order wins per code), and the client's reservation. `GET /dhcp/scopes/{prefix}/effective-options?mac=&client_id=&vendor_class=&user_class=` shows the result, each option with its level and owner, and the reservation the client has. Pool options depend on the address the allocator picks and are shown on the pool. Which classes and policies match a client is WP8.4's compiled matcher; until it lands the route matches none, and the policy level is empty.

## 5. Classes and policies

A class (`/dhcp/classes`) is a named match on the request that holds when any of its matches holds: vendor class (option 60, exact or prefix), user class (option 77), MAC address with wildcards, client identifier, relay agent circuit-id and remote-id, client architecture (option 93) and host name (exact or prefix). A name is unique; a class needs 1 to 64 matches. A class a scope, a pool or a policy names is not deleted (`dhcp.class.in_use`, parameter `by` with `scope:<prefix>`, `pool:<range>` and `policy:<id>`).

A policy (`/dhcp/policies`) belongs to a scope or, without one, to the server, where it applies after the scope's own. Its condition joins 1 to 64 terms with `and` or `or`: a class, a class negated, a match, a match negated (P3-Q12, the shape of Windows DHCP policies). Its action restricts the clients to an address range inside the scope's network (`dhcp.pool.outside` otherwise), sets lease times and DDNS settings; its options are the option set of `policy:<id>`. The name is unique in the scope; without `order` a new policy goes after the last of its scope. Policies apply in order, the first matching policy per action winning. Classes and policies are stored and validated now; matching them against requests is WP8.4's.

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
tenko dhcp class list | show ID | create NAME --match JSON... | delete ID
tenko dhcp policy list | show ID | create --file POLICY.json | delete ID
tenko dhcp filter list | add MAC-PATTERN --allow|--deny [--note TEXT] | delete ID
```

Every command takes `--json` for the API's answer as is. `crates/tenko/tests/acceptance_dhcp_config.rs` runs the configuration through the real binary: a scope, an exclusion, a pool's lease times, options from `CODE=HEXDATA` at two levels, a custom definition, a class, a filter and the settings, the effective options of a client, and the prefix that IPAM keeps while the scope exists.

The web UI's DHCP area (`/dhcp`) has the scope list with utilization, the scope page with its pools, exclusions, options and effective options, the shared networks, the options with the catalog and the custom definitions, the classes and policies, the MAC filters, and the DHCP section of the settings (`/settings/dhcp`).
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

The client is its client identifier (option 61) when it sends one, else its hardware type and `chaddr` (RFC 4361, RFC 6842); option 61 is echoed in every reply. A MAC address the deny list matches is dropped (`filtered`, DHCP-08). A scope marked restricted serves only clients the allow list matches and clients with a reservation in it (TGL-17); everyone else is dropped as `filtered`.

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

The value of a code is the most specific level's: the reservation's (host), the pool's, then the scope's, which the image holds already merged with the shared network's and the server's; policies add a level between pool and host in WP8.4. The reply carries option 53, 54 and the lease times first, then the subnet mask (configured, else the scope's prefix length; RFC 2132 wants it before the routers), then every option the client lists in option 55 in the client's order (a split option 55 is joined first), then the routers, the DNS servers and the domain name when they are set and were not asked for (as Kea sends them), then option 61, option 81 and option 82 unchanged and last (RFC 3046). Codes the server manages (`SERVER_MANAGED_V4`) never come from an option set. Room for the closing options is kept; an option that does not fit within the client's size (option 57, else 548 octets) is left out whole. A value above 255 octets goes out as consecutive instances (RFC 3396). Overload into `file` and `sname` stays off until the scope has a switch for it.

Option 81 is answered as a server that performs no DNS update (RFC 4702 section 4): N set, S clear, O set when the client asked for S, E as the client sent it, the client's name echoed. DDNS (WP8.3) changes the flags when it writes the records.

### 9.6 The listeners and workers

`DhcpServer::start` binds every `[dhcp] listen` entry through `socket2`, the safe socket API of the DNS role, and starts the workers of ADR 0009: one `SO_REUSEPORT` socket per worker on Linux, one shared socket on Windows. `socket2` 0.6 has no safe way to ask for `IP_PKTINFO`, so the receiving interface and address come from the binding instead:

| Mode | Linux | Windows |
|---|---|---|
| `relay` | Binds the unicast address on port 67; only relayed and unicast traffic arrives. Needs `CAP_NET_BIND_SERVICE` only | The same |
| `direct` | Binds `0.0.0.0` on port 67 with `SO_BINDTODEVICE` to the entry's interface and `SO_REUSEADDR`, so that each interface has its socket and its broadcasts; without an interface name one socket hears every link. Replies to a hardware address go out as broadcasts until the link-layer socket of WP7.5 | Binds the interface's address, on which Windows delivers that interface's broadcasts; replies to a hardware address are always broadcast |

A worker runs the engine and sends an OFFER, a NAK or an INFORM's ACK at once. For an ACK it copies the lease change and the reply into a slot of a fixed table under a ticket and hands the change to the `LeaseStore`; it never waits for the disk. The committer thread takes the store's completions: a committed change is applied to the lease table at once (the feed's copy of the row changes nothing later, `LeaseTable::apply`) and its ACK is sent; a refused one is dropped and counted. A full slot table or store queue drops the request as `queue`.

The counters are per worker, relaxed atomics: `tenko_dhcp_packets_total` by type and outcome, `tenko_dhcp_dropped_total` by reason, the NAKs, the DECLINEs, the refused commits, and the histograms of DISCOVER to OFFER, REQUEST to ACK and the commit; `DhcpServer::metrics` sums them, and the role registers them in WP7.5.

### 9.7 Tests and measurements

- `tests/engine.rs`: a table of RFC 2131 cases (every message type and REQUEST state, the NAK rules, the server identifier, the broadcast flag, every destination) and the cases around it (lease times and the commit, DECLINE's hold, RELEASE, the NAK's options, the order of option 55 and the split routes, reservation options, option 81, link selection with the server identifier override and option 118, the store refusal, restricted scopes, a full pool).
- `tests/engine_corpus.rs`: the corpus `fixtures/requests/*.hex` (requests of Windows, ISC dhclient, systemd-networkd, Android, macOS and PXE firmware modelled by hand on the option order and the parameter request lists these clients send, relays with option 82, renewals, INIT-REBOOT, DECLINE, RELEASE, INFORM; documentation addresses and MACs) answered octet for octet as recorded in `fixtures/requests/expected/`, every reply decoded by `dhcproto` and checked for option 53 first, option 61 and option 82 echoed, option 82 last, the size limit and the order of option 55. `TENKO_BLESS=1` rewrites the recorded answers after a deliberate change. WP7.6 adds requests captured in the lab.
- `tests/engine_allocator.rs` and `tests/engine_server.rs`: the allocator against the reference, and a relay listener on loopback running DORA, a renewal, a release and a refused commit through `MemLeaseStore`.
- `crates/tenko-dhcp/examples/dhcp_server.rs` serves the engine on a port for perfdhcp and carries a load client; `bench/phase3-dhcp` runs M26 to M28 with it on loopback.

What the engine leaves to later packages: the conflict probe before an offer and the DECLINE rate limit and observation (WP8.5); classes and policies, the class restrictions of scopes and pools included (WP8.4: the image carries them and the engine does not match them yet); DDNS (WP8.3); the link-layer reply and the role's wiring, configuration and metrics registration (WP7.5).
