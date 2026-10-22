# DHCP: the wire format

This page describes how Tenko DDI reads and writes DHCP messages and, as Phase 3 lands, how the `dhcp` role serves them. It is for builders of the DHCP server and for operators who want to know what a node accepts on the wire. Section 1 describes the DHCPv4 wire codec in `crates/tenko-dhcp` (`tenko_dhcp::v4`); where this page and the code differ, the code is right. The requirements are DHCP-01 to DHCP-08 and DHCP-13 in [REQUIREMENTS.md](REQUIREMENTS.md); the RFCs and their status are in [CONFORMANCE.md](CONFORMANCE.md).

Contents:

1. [The wire format](#1-the-wire-format)
7. [Leases](#7-leases)

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

## 7. Leases

A lease is a row of `dhcp.leases` in the replicated store, committed before the ACK (decision P3-Q1, [ADR 0019](adr/0019-dhcp-data-model-and-lease-path.md)); there is no lease file. The `dhcp` role serves from a lease table in memory that equals the rows, and never reads the store while it answers. The code is `tenko_dhcp::lease` (WP7.2); the contracts it implements are in [dhcp-contracts.md](dhcp-contracts.md), section 3.

### 7.1 The lease change

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

### 7.2 When the ACK leaves

The ticket of a change completes, and the worker sends the ACK, only after the store has answered the batch (on one node: its log entry is on disk and applied) and the committer has applied the row to the role's table at the commit's revision. A change that has not committed within 2 seconds of its hand-off completes as failed and the request is dropped, as the DNS update path answers SERVFAIL when its index wait passes ([dns.md](dns.md)); a commit that lands later still reaches the table, and the client's retry finds its lease. The time from the hand-off to the completion is `tenko_dhcp_commit_duration_seconds`.

### 7.3 The table

The table (`LeaseIndex`) holds every row by VRF and address and, per scope, by client identity, with each client's rows beside its index entry. It takes rows from two sides: the committer's own commits at once, and the feed's copy of every row (`DhcpFeed`: an image at a revision, then the deltas in revision order, a new image after a snapshot install). A row replaces the one held unless the held one is newer: written at a later revision when both revisions are known, else with a later client transaction time. So the feed's copy of an own commit changes nothing, an older copy never overwrites a newer row, and a new image keeps the rows of commits after its revision until the deltas bring them. A delta that does not follow the revision held is a gap, and the role reads a new image.

At start the table is rebuilt from the store, page by page (`rebuild_from_view`). The measured figures are in `bench/phase3-dhcp/results/` (E24, M32): a table of 100,000 leases rebuilds well within the 5 seconds the plan sets.

### 7.4 Expiry

Expiry is a leader service (`dhcp.expiry`, every 10 s). It finds the rows whose state has ended (an active binding past its end, an abandoned address past its hold) and writes them as `expired`, with a history row each, in batches of 256 rows. Each batch carries the leader fence and a version precondition per row: a renewal committed in between makes the batch fail and the row is looked at again in the next round, and a controller that has lost the leadership writes nothing. The client index does not move. The same round drops ended offers from the offer hold. Expiry does not decide whether an address is free (the allocator already treats a binding past its end as free); it makes the row say so, records the event and lets DDNS remove the records (WP8.3). It counts `tenko_dhcp_expired_total`.

### 7.5 History retention

`dhcp.history` is bounded by a retention in days (P3-Q13): the node's `[dhcp.history] days` if set, else the replicated `history_days` of the DHCP settings, else the security profile's default.

| Profile | Days |
|---|---|
| Home | 30 |
| Standard | 90 |
| Hardened | By policy; 90 unless set, and every purge is in the audit export |
| Lab | 7 |

A leader service (`dhcp.history.purge`, hourly) deletes the rows older than the retention in batches of 1,000 under the leader fence, each batch with one audit record `dhcp.history.purge` that names the cut-off and the count. `tenko_dhcp_history_purged_total` counts the purged rows and `tenko_dhcp_history_rows` the rows held (counted once per term of office, then kept from the writes and the purges). Every lease change writes one row, renewals included: a network of 100,000 clients on one-hour leases writes about 55 rows a second, so at that size the retention is a setting to choose with care.

### 7.6 While the store refuses

On one node the store refuses a write only when its disk fails, or through the test hook `TENKO_TEST_REFUSE_WRITES_FILE`; in Phase 5 also when a node loses its quorum. The role then promises nothing it has not committed (P3-Q14):

- a renewal, a rebind or a request for the address a client holds is answered with an ACK for the time the lease has left: no extension, nothing written;
- every other request is dropped, and the client retries; it counts `tenko_dhcp_dropped_total{reason="store_refused"}`;
- every refused write counts `tenko_dhcp_store_refused_total`, and the health finding `dhcp.role.store_refused` is raised with the time of the first refusal and the counts since.

After a refusal the role tries the store again after one second: the next change goes to the store, a commit clears the finding, and another refusal waits another second. No probe write is made.

### 7.7 Tests and the crash test

The tests are in `crates/tenko-dhcp/tests/`: `lease_table.rs` (the table against the reference table on random sequences, the index moves, the feed, own commits against older copies), `lease_store.rs` (the batches against the reference lease store, a burst of concurrent changes, another client's binding, the queue, a slow commit, a refusing store), `lease_services.rs` (expiry, its fence and its race with a renewal, the offer hold, the retention and the purge), `lease_refusal.rs` (the refusal path on the Raft store with the hook, in a child process), `lease_alloc.rs` (no allocation on the hand-off, the lookups, the offer hold and the refusal gate), `lease_rebuild.rs` (the rebuild of a large table and the commit latency) and `lease_crash.rs`.

The crash test (E24, M32) kills a node under load and restarts it, again and again. The node is a child process of the test: it opens the Raft store, rebuilds its table and runs 200 clients that request, renew and release through the allocator, the offer hold and the lease store, and it prints a line for an ACK only after its ticket completed. The test kills it at a random moment (SIGKILL on Unix, TerminateProcess on Windows), opens the data directory and checks that every ACK received is in the rows at its revision or later, that its history row is there, that the rebuilt table equals the rows and the client index, and that the history never gives an address to a second client while the first one's binding had not ended. `bench/phase3-dhcp/scripts/crash-test.sh` runs it 20 times with the rebuild and the latency measurement; the results, and the procedure of the power-off runs on the lab VM, are in `bench/phase3-dhcp/results/`. Until the `dhcp` role exists in the binary (WP7.5), the crash test drives the lease path through this test entry point rather than through `tenko serve`.
