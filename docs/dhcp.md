# DHCP: the wire format

This page describes how Tenko DDI reads and writes DHCP messages and, as Phase 3 lands, how the `dhcp` role serves them. It is for builders of the DHCP server and for operators who want to know what a node accepts on the wire. Section 1 describes the DHCPv4 wire codec in `crates/tenko-dhcp` (`tenko_dhcp::v4`); where this page and the code differ, the code is right. The requirements are DHCP-01 to DHCP-08 and DHCP-13 in [REQUIREMENTS.md](REQUIREMENTS.md); the RFCs and their status are in [CONFORMANCE.md](CONFORMANCE.md).

Contents:

1. [The wire format](#1-the-wire-format)

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
