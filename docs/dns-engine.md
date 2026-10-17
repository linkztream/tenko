# DNS engine

This page describes the engine of the `dns` role: how a query travels from a socket to its answer, how the workers use sockets on each platform, how the index is laid out and kept current, the order of the lookup, EDNS and cookies, TCP, the limits and their settings, the metrics and the allocation rule. It is for operators who size and tune a node and for builders of the later Phase 2 packages. It is written as section 12 ("The engine") of `docs/dns.md` and moves there when that file exists. The decisions behind it are [ADR 0009](adr/0009-dns-wire-format-and-udp-io.md) (wire format and UDP I/O) and [ADR 0017](adr/0017-dns-data-model-and-serving-path.md) (data model and serving path); the contracts are in [dns-contracts.md](dns-contracts.md). The code is `crates/tenko-dns`; where this page and the code differ, the code is right.

Contents:

1. [The path of a query](#1-the-path-of-a-query)
2. [Workers and sockets](#2-workers-and-sockets)
3. [The index](#3-the-index)
4. [The lookup](#4-the-lookup)
5. [EDNS and cookies](#5-edns-and-cookies)
6. [TCP](#6-tcp)
7. [Settings and limits](#7-settings-and-limits)
8. [Metrics and the worker layout](#8-metrics-and-the-worker-layout)
9. [No allocation per query](#9-no-allocation-per-query)
10. [Measurements](#10-measurements)
11. [Known limits](#11-known-limits)

## 1. The path of a query

| Step | Where | What |
|---|---|---|
| Receive | `transport::udp`, `transport::tcp` | A UDP worker blocks in `recv_from`; a TCP connection reads a length-prefixed message |
| Parse | `codec` (`DomainCodec` on `domain` 0.12.3) | Header, the one question, OPT with the cookie, TSIG positions; a message that is no query is dropped, one that does not parse gets a header-only FORMERR |
| EDNS and cookies | `respond` | BADVERS for an EDNS version other than 0; the cookie check (section 5) |
| Resolve | `authoritative` (the `Resolver`) | View, index, policy, forwarder (section 4) |
| Build | `codec` | The answer within the transport's limit, with OPT, the cookie, an extended error and the truncation rules |
| Count | `respond`, `metrics` | Queries by transport, view and RCODE; the latency from arrival to answer; the query log entry |
| Send | the transport | `send_to`, or the TCP write when no pipelined query waits |

Every transport calls the same `Responder`, so UDP and TCP answer alike; a query the resolver forwards is handed to the forwarder's intake (`ForwardSink`, WP4.3), which answers the client later through the transport's reply path.

## 2. Workers and sockets

| Platform | Layout | Why |
|---|---|---|
| Linux | One blocking thread per worker, each with its own UDP socket bound with `SO_REUSEPORT` to the listen address | The kernel spreads clients over the sockets by flow hash; Spike B measured this layout scaling to 32 workers where a shared socket stopped at 16 |
| Windows | One blocking thread per worker, the workers of an address sharing one UDP socket | Windows has no load-balancing `SO_REUSEPORT`; threads and tokio tasks measured the same, threads idle more cheaply |

Each worker has its own receive buffer (65,535 octets, so a query is never cut), its own query buffers and its own counters; it reads the wall clock once a second, not per query. Workers wake every 200 ms to see a stop. `recvmmsg`, UDP GSO and a BPF steering program are not used (ADR 0009 keeps them as later optimisations).

Because `SO_REUSEPORT` balances by flow hash and not by load, a few clients can leave workers idle: the worker layout (section 8) shows the datagrams per worker so that this is visible. `--mode shared` (the setting `udp.socket`) switches Linux to the shared socket.

Every listen address gets UDP and TCP; an IPv6 address is bound IPv6-only, so `0.0.0.0:53` and `[::]:53` are listened on side by side (DNS-04). The worker count applies per listen address.

## 3. The index

The index (`tree::ZoneIndex`) holds one name tree per zone and scope, in two layers:

- **The base** is immutable: every owner name and every empty non-terminal is stored once in one arena of wire names, the RRsets as runs of the stored record data (the uncompressed wire form of the rows, which the codec copies into the answer), the nodes and RRsets in flat vectors, and an open-addressing table of 4-octet slots maps a name to its node. A lookup hashes the name once and compares it with the arena.
- **The overlay** holds the nodes changed since the base was built, or tombstones for removed ones. A lookup reads it first when it is not empty. When it holds more than an eighth of the base (and more than 1,024 nodes), the writer folds it into a new base.

The index is immutable as a whole: a delta produces a new index that shares every base and every zone it does not touch and copies only the overlays it changes. The catalog (`catalog::Catalog`: the index, the view table and the forwarding table) sits behind one pointer swap (`arc-swap`, as ADR 0002's index swap): a worker loads the current catalog for each query without a lock, and the one writer (`catalog::follow`) applies the feed's deltas in revision order on tokio's blocking pool and stores each new catalog. A reset of the feed (a snapshot install) builds a new catalog and swaps it whole, so answers never stop (M1). A delta that does not follow the revision held makes the writer ask the feed for a new image.

RRsets of a zone the index does not hold (they arrived before their zone, or their zone left) are kept aside and join the zone when it arrives. `ZoneIndex::stats` reports the zones, scopes, nodes, RRsets, records and name octets of the bases, the overlay nodes and the RRsets kept aside (for M18 and the health view).

The reference implementation `MemIndex` is the test oracle: the tests build both from the same rows and compare every lookup over a generated zone of 100,000 names and after every delta of a random sequence, and a hand-written corpus pins the special cases.

## 4. The lookup

The order of one query (plan sections 2.2 and 2.3):

1. **Header.** An opcode other than QUERY is NOTIMP. A signed query is NOTAUTH until the TSIG keys reach the engine (WP6.2). A class other than IN is REFUSED. The meta types OPT, TKEY and TSIG are FORMERR; AXFR and IXFR are REFUSED with the extended error "Prohibited" until transfers exist (WP6.1); MAILA and MAILB are NOTIMP.
2. **Rate limiter**: the query is admitted or dropped (`RateLimiter::admit_query`; WP5.2 implements RRL).
3. **View** (DNS-20): the first view in `order` whose rules all match (client subnet, transport, local address, query type, time of day, query name) wins; none matching is the implicit default view, which sees the default scope of every zone. A view's weights pick one scope per zone, with a value derived from the client address so that one client keeps seeing the same scope.
4. **Zone**: the served zone (primary or secondary) with the longest apex at or above the name. A stub, forward or RPZ zone is not answered from.
5. **Name**: the exact name first; else its closest encloser. On the way from the apex down, a zone cut (NS below the apex) refers, except for a DS query at the cut itself, which the parent answers; a DNAME above the name redirects it. A name that does not exist is answered from the wildcard at its closest encloser (RFC 4592), with the question name as the owner.
6. **Chains**: a CNAME is followed inside the index and a DNAME's CNAME is synthesized (owner the current name, TTL the DNAME's, RFC 6672), up to eight steps in all; a loop or a longer chain stops with what was found. A synthesized name over 255 octets is YXDOMAIN.
7. **Sections** (minimal responses): a positive answer carries no NS in the authority section; the additional section carries the A and AAAA RRsets of the targets of MX, SRV and NS answers that the index holds, each target once. A referral carries the NS RRset (and the DS for a client with the DO bit), then the in-domain glue, which must fit (else the answer is truncated, RFC 9471), then the other glue inside the parent zone, which is left out when it does not fit. NODATA and NXDOMAIN carry the zone's SOA with the TTL of RFC 2308: the smaller of the SOA's TTL and its MINIMUM. NXDOMAIN at the end of a chain is the RCODE of the last name (RFC 6604). A query for ANY gets one RRset of the name (RFC 8482).
8. **Bits**: AA for an answer from a zone, clear for a referral; RA when a forwarder is configured; AD never (no validation).
9. **Outside the zones**: the policy (`PolicyEngine`: RPZ and block lists, WP5.2) may block with NXDOMAIN, NODATA or a redirect address, with the extended error "Blocked"; else, when the client asked for recursion, the forwarding rule with the longest suffix (a rule of the query's view before one of all views), or the default forwarder of the configuration, gets the query; else REFUSED with the extended error "Not Authoritative".
10. **Rate limiter** on the response (`admit_response` by response kind and zone): send it, slip it (an empty answer with TC, so a real client retries over TCP) or drop it.

## 5. EDNS and cookies

- **EDNS** (RFC 6891): the server's UDP size is 1,232 octets (DNS flag day 2020; the setting `edns.udp_size`, 512 to 4,096). A UDP answer is at most the requester's size clamped to 512 and the server's size, 512 octets without EDNS; TCP answers go up to 65,535. The OPT record of the answer advertises the server's size, echoes the DO bit, carries the extended RCODE (BADVERS 16, BADCOOKIE 23), the cookie and an extended error (RFC 8914: "Blocked" 15, "Prohibited" 18, "Not Authoritative" 20, "Not Supported" 21). Unknown options are ignored; a second OPT record, an OPT not owned by the root or a malformed option is FORMERR.
- **Truncation**: when an answer or authority record does not fit, the answer is the header, the question and OPT with TC set; additional records that do not fit are left out without TC, except required glue.
- **Cookies** (RFC 7873) in the interoperable server-cookie form of RFC 9018: version 1, a 32-bit timestamp and a SipHash-2-4 of the client cookie, those fields and the client address under a 16-octet secret. The secret is the node's (`CookieSecret`, owned by the server): random at start and replaced every 24 hours, the previous one staying valid, so a cookie is accepted for its lifetime of one hour (and up to five minutes ahead of the clock) across a rotation. Every query with a client cookie gets the client cookie and a fresh server cookie back; a malformed cookie is FORMERR.
- **Cookie modes** (`cookies`): `on` (the default) answers a missing or invalid server cookie normally with a fresh one; `required` answers a UDP query whose client sent a cookie without a valid server cookie with BADCOOKIE and a fresh cookie, so that a spoofed source gets no amplified answer; queries without any cookie and every TCP query are answered normally; `off` ignores cookies.

## 6. TCP

DNS over TCP follows RFC 7766 on the tokio runtime: each message is preceded by its two-octet length; a client may pipeline queries, which are answered in arrival order, and the answers are written together when no further query is buffered (or 32 KiB of answers wait). A connection is closed after the idle time without a query (10 seconds), when a message is cut, or when the server stops. The node accepts at most 1,000 open connections and 10 from one client address; a connection over either cap is closed at once and counted. TCP never answers BADCOOKIE. The query buffers are kept per runtime thread, so a TCP query allocates nothing either.

## 7. Settings and limits

The `[dns]` keys of the configuration (written by WP4.3 in `deploy/tenko.example.toml`) and the fields of `server::ServerConfig` they set. The keys marked (proposed) are not in the WP4.3 list; WP4.3 decides whether they become keys or stay at their defaults:

| Key | Field | Default | Meaning |
|---|---|---|---|
| `listen` | `listen` | `0.0.0.0:53`, `[::]:53` | Addresses for UDP and TCP; port 53 needs `CAP_NET_BIND_SERVICE` on Linux |
| `workers` | `udp.workers` | the CPU count | UDP workers per listen address |
| `udp.socket` (proposed) | `udp.mode` | `reuseport` on Linux, `shared` elsewhere | Socket per worker or one shared socket |
| `udp.recv_buffer`, `udp.send_buffer` (proposed) | `udp.recv_buffer`, `udp.send_buffer` | 8 MiB | `SO_RCVBUF` and `SO_SNDBUF`; the system caps them (`net.core.rmem_max`) |
| `tcp.max_connections` | `tcp.max_connections` | 1000 | Open TCP connections per node |
| `tcp.per_client` | `tcp.per_client` | 10 | Open TCP connections per client address |
| `tcp.idle_secs` | `tcp.idle` | 10 | Seconds without a query before a TCP connection is closed |
| `edns.udp_size` | `edns_udp_size` | 1232 | The server's EDNS UDP size, 512 to 4096 |
| `cookies` (proposed) | `cookies` | `on` | `on`, `required` or `off` (section 5) |

The fixed limits: a CNAME and DNAME chain of eight steps; 8,192 records and 192 KiB of names and data per answer before the build (an answer over that is truncated); messages up to 65,535 octets. The metrics switch of M22 is not a configuration key: metrics are always on in a node, and only the example server can switch them off to measure their cost.

## 8. Metrics and the worker layout

The engine counts `tenko_dns_queries_total{proto,view,rcode}` and observes `tenko_dns_query_duration_seconds{proto}` (50 µs to 2 s, from the arrival of a query to its answer) on the calling thread's shard of the registry (OPS-21); `metrics::register` seals and registers both at the role's start. `view` is `default` for the implicit default view and `named` for any configured view (per-view series come with view management, WP6.4); `rcode` is one of `noerror`, `formerr`, `servfail`, `nxdomain`, `notimp`, `refused`, `notauth`, `badvers`, `badcookie` or `other`. Dropped and forwarded queries are not counted there.

`Server::layout` reports the socket mode, the workers per address and, per UDP worker, its address, its socket and its counters (received, sent, dropped, forwarded, receive and send errors), and the TCP listeners with the open connections and the refused ones. WP4.3 shows it in the node's health view; uneven `received` counts across `reuseport` workers are the flow-hash effect of section 2.

## 9. No allocation per query

The query path allocates nothing once its buffers exist (ADR 0009): the request lives in fixed-size fields, the answer in an arena reserved per worker, the output reuses its vector, names synthesized from a DNAME live in fixed buffers, the catalog is read through the swap, and metrics are relaxed atomic adds. `crates/tenko-dns/tests/alloc.rs` enforces it with a counting global allocator: after proving that it sees a deliberate allocation, it runs parse and build, truncation and FORMERR, index lookups, and the whole path of thirteen kinds of query through the responder, the authoritative resolver, the production index and the codec, with metrics and cookies on, and fails on a single allocation. Only a query handed to the forwarder is copied, off the query path. A change that allocates per query fails this test.

## 10. Measurements

M16 (QPS per core on loopback, UDP and TCP) measures `crates/tenko-dns/examples/authoritative.rs`, which serves the `zonegen` zone of `bench/phase2-dns` through this engine until the `dns` role runs in `tenko serve` (WP4.3); the results are in `bench/phase2-dns/results/2026-10-17-m16-loopback.md`, against the Spike B baseline of the same harness. In short (loopback, upper bounds, 8 client sockets with 32 queries in flight each):

| Platform | UDP, 1 / 4 / 8 workers | QPS per server core, UDP | TCP, 1 / 4 / 8 runtime threads |
|---|---|---|---|
| Windows 11 (shared socket) | 124k / 448k / 698k | 125k / 113k / 88k | 430k / 550k / 543k |
| WSL2, musl (`SO_REUSEPORT`) | 130k / 744k / 1.11M | 130k / 187k / 222k | 464k / 1.67M / 2.05M |
| WSL2, musl (shared socket) | – / 740k / 1.78M | – / 185k / 223k | |

At 4 and 8 workers the engine costs the same CPU per query as the Spike B responder; at one worker it costs 1 to 1.7 µs more. With few client sockets `SO_REUSEPORT` leaves workers idle (section 2).

## 11. Known limits

- The UDP sockets do not read the destination address of a query (no `IP_PKTINFO`). On a host with more than one address, a socket bound to the wildcard address may answer from another source address than the client asked, which the client discards; such a node lists each of its addresses in `listen` (WP4.3 may expand the wildcard into the host's addresses at start). For the same reason an interface rule of a view compares the address a socket is bound to.
- When Tenko serves both a parent zone and its child, a DS query at the child's apex is answered from the child zone (the longest apex wins), where RFC 4035 (section 3.1.4.1) asks for the parent's DS; DNSSEC (WP6.3) handles this case.
- A delta copies the overlay of each scope it touches, and folding an overlay into a new base is linear in the scope's size; very large zones with a high rate of dynamic updates (M21) may need an incremental base later.
- `SO_REUSEPORT` spreads by flow hash: a load generator with few sockets reaches only some workers (section 2).
