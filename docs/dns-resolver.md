# DNS: the resolver side

- Scope: how a node answers names outside the zones it serves: the forwarder, its rules and stub zones, the recursion access lists, the cache with serve-stale and prefetch, and the upstreams over plain DNS, DNS over TLS and DNS over HTTPS (Phase 2, plan section 2.8; DNS-02, DNS-08, DNS-15, DNS-23, TGL-14, TGL-22). For operators who make a node the resolver of their clients, and for the builders of the later Phase 2 packages.
- The authoritative side (zones, records, the `dns` role, the engine) is [dns.md](dns.md); the contracts are [dns-contracts.md](dns-contracts.md). The code is `crates/tenko-dns` (`forward`, `cache`, `pool`, `upstream`, `outbound`, `forwarders`).

Contents:

1. [The resolver side and the lookup order](#1-the-resolver-side-and-the-lookup-order)
2. [Forwarding rules, stub zones and the recursion access list](#2-forwarding-rules-stub-zones-and-the-recursion-access-list)
3. [The cache, serve-stale, prefetch and the flush](#3-the-cache-serve-stale-prefetch-and-the-flush)
4. [Upstreams: the pool, the transports, TLS, 0x20 and the settings](#4-upstreams-the-pool-the-transports-tls-0x20-and-the-settings)
5. [Response policy zones and block lists](#5-response-policy-zones-and-block-lists) (WP5.2)
6. [Rate limiting](#6-rate-limiting) (WP5.2)
7. [DoT and DoH served to clients](#7-dot-and-doh-served-to-clients) (WP5.3)
8. [The query log and dnstap](#8-the-query-log-and-dnstap) (WP5.4)
9. [The home cut-over](#9-the-home-cut-over) (WP5.6)

## 1. The resolver side and the lookup order

A node with the `dns` role answers from its zones first and forwards the rest: Tenko has no recursive resolver of its own in Phase 2 (DNS-03 is Phase 5), so recursion is forwarding to upstream resolvers with a cache in front (DNS-02). One query goes through these steps, in this order (plan sections 2.2 and 2.3):

| Step | Where | What |
|---|---|---|
| 1. Header, rate limiter, view | `authoritative` | As for every query ([dns.md](dns.md) section 12.4): the opcode, the class, the meta types, the rate limiter's admission, then the view whose rules match first, else the implicit default view |
| 2. Zones | `authoritative` | A name in a primary or secondary zone is answered from the index, whatever the client asked for; stub and forward zones are not answered from |
| 3. Policy | `authoritative` (`PolicyEngine`) | Outside the zones the policy decides first: RPZ and block lists (WP5.2, section 5) |
| 4. Recursion desired | `authoritative` | A query without RD gets REFUSED with the extended error "Not Authoritative" (20) |
| 5. Recursion check | `forward` (on the query path) | The view's recursion access list, or the profile's default (section 2.3); a client that may not recurse gets REFUSED with the extended error "Prohibited" (18) |
| 6. A route | `forward` (on the query path) | A forwarding rule, a stub zone or the default forwarder covers the name, else REFUSED with "Not Authoritative" |
| 7. The cache | `cache` (on the query path) | A fresh entry answers at once, with the TTLs lowered by the entry's age (section 3) |
| 8. The upstreams | `forward`, `pool`, `upstream` (off the query path) | The query is copied and handed to the forwarder, which asks the route's upstreams, fills the cache, answers stale when the upstreams fail (section 3.3) and answers the client through the transport's reply path |

Steps 1 to 7 run on the worker that received the query and allocate nothing (ADR 0009; `crates/tenko-dns/tests/alloc.rs` runs cache hits in a view with a recursion access list and refused queries through the counting allocator). Step 8 runs on the tokio runtime, up to 1,024 queries at once, from a queue of 4,096; a full queue drops the query and the client retries.

Every name outside the zones reaches the forwarder, which decides; so a node sets RA in every answer. The forwarded answers are counted in `tenko_dns_queries_total` with the RCODE relayed and timed from the hand-over to the answer; cache hits are counted and timed as any answer of the query path.

What is not in Phase 2: DNSSEC validation (the DO and CD bits go upstream and the signatures come back to a client that asked with DO, but AD is always clear), a recursive resolver of Tenko's own, aggressive use of NSEC (RFC 8198), and the client-subnet option (RFC 7871).

## 2. Forwarding rules, stub zones and the recursion access list

### 2.1 Forwarding rules

A forwarding rule (`dns.forwarders`, DNS-02) sends the names at or below its suffix to its upstreams: 1 to 16 addresses, each with an optional port and, for DoH, an optional path, all over one transport (`plain`, `dot` or `doh`; DoT and DoH need `tls_name`, the name in the upstreams' certificates). A rule applies in one view or in all views; there is one rule per suffix and view.

The rule for a name is the one with the longest suffix; at the same length a rule of the query's view goes before a rule of all views. The root suffix `.` covers every name: a root rule is the default forwarder of the store, and it wins over `[dns] forwarders` of the configuration file, which applies only when no rule of the store covers a name. A node needs neither: with no rule, no stub zone and no configured upstream, names outside the zones are refused.

| Route | Operation | Scope |
|---|---|---|
| `GET /api/v1/dns/forwarders` | `list_dns_forwarders` | `dns.read`: the rules by suffix, the root first; paged with `cursor` and `limit` |
| `POST /api/v1/dns/forwarders` | `create_dns_forwarder` | `dns.write`: `suffix`, `upstreams[]` (`address`, `port`, `path`), `transport`, `tls_name`, `view`, `description` |
| `GET /api/v1/dns/forwarders/{id}` | `get_dns_forwarder` | `dns.read`, with the `ETag` of the row |
| `PATCH /api/v1/dns/forwarders/{id}` | `update_dns_forwarder` | `dns.write`, `If-Match` optional; an empty `tls_name` or `description` clears it, `all_views: true` makes the rule apply in every view |
| `DELETE /api/v1/dns/forwarders/{id}` | `delete_dns_forwarder` | `dns.write`, `If-Match` optional |

Errors: `dns.forwarder.invalid` (400, parameters `field` and `reason`: no upstream or more than 16, a DoT or DoH rule without `tls_name`, a path on a plain or DoT upstream or one that does not start with `/`, port 0, a view that does not exist, a second rule for the same suffix and view), `dns.forwarder.not_found` (404), 412 for a stale `If-Match`. Each change is an inline job with its audit record (`dns.forwarder.create`, `dns.forwarder.update`, `dns.forwarder.delete`, the suffix in the context). The role's catalog follows the rows through the feed: a change answers queries from the next revision the node applies, with no restart.

The command line: `tenko dns forwarder list|create|get|update|delete`. A rule is named by its identifier or its suffix (when one rule has it):

```sh
tenko dns forwarder create . --upstream 192.0.2.1 --upstream 192.0.2.2
tenko dns forwarder create example.net --transport dot --tls-name resolver.example.net \
  --upstream 198.51.100.53 --upstream '[2001:db8::53]:853'
tenko dns forwarder create corp.example.test --transport doh --tls-name dns.example.test \
  --upstream 192.0.2.80:443/dns-query
tenko dns forwarder update example.net --all-views
tenko dns forwarder delete corp.example.test
```

A rule for a name inside a zone the node serves is never used: the zone answers first.

### 2.2 Stub zones

A stub zone is a zone of kind `stub` whose `source` names the servers to ask (`POST /api/v1/dns/zones` with `"kind": "stub"` and `"source": {"primaries": [{"address": "192.0.2.53"}]}`; the command line does not set `source` yet). The forwarder asks them for the NS set of the apex (without RD) and sends the queries for names in the zone to the name servers it names:

- The addresses come from the glue of that answer, else from A and AAAA queries for the name server's name through the forwarder's own route for it (a rule or the default forwarder; never another stub zone). A name server is asked on port 53, or on the port of the source server with its address.
- The learnt servers are kept for the NS set's TTL, between 30 seconds and one day, then learnt again on the next query. When learning fails the servers learnt before keep serving, and another attempt is made after 30 seconds.
- A stub zone whose servers were never learnt answers SERVFAIL; it is listed with the reason in `problems` of `GET /api/v1/nodes/{id}/dns`.
- Between a stub zone and a rule, the longer suffix wins; at the same length the stub zone.

The queries to a stub zone's servers are plain DNS with the pool's health, round-trip times and 0x20 (section 4), as for a rule. Zones of kind `forward` are not used by the forwarder; a forwarding rule does that.

### 2.3 The recursion access list (TGL-22)

Who may recurse is decided per view, before the cache is read, so that one client cannot see what another asked (cache snooping) and the node is no open resolver by accident:

- A view with `recursion` set names an access list (`dns.acls`, [dns.md](dns.md) section 6): the first matching entry decides, and no match refuses. A key entry never matches a recursive query (queries are not signed). A list that does not exist (deleted) allows no client of the view; the node lists the view in `problems` of its status.
- A view without `recursion`, and the implicit default view, follow the profile in force:

| Profile | Default |
|---|---|
| Home, Standard | The prefixes IPAM knows (every prefix of `ipam.prefixes`, whatever its status) and loopback |
| Hardened | No client: every view names its list |
| Lab | Every client (an open resolver) |

The node reads the profile and the prefixes at start and again after every change of either (a follower watches `auth.settings` and `ipam.prefixes`), so a new prefix in IPAM is allowed to recurse within a second, and finishing first-run setup with another profile changes the default without a restart. Before setup the bootstrap profile of `[profile] name` applies. An IPv4-mapped IPv6 client address is its IPv4 address.

To widen or narrow the default, create a view whose rules match the clients in question (or a view without rules, last in order, which matches every query) and give it an access list. View management (`/dns/views`) comes with WP6.4; until then views are rows the store holds from a migration or a test.

A refused client gets REFUSED with the extended error 18 ("Prohibited"); refusals are counted in `refused` of `dns.stats`.

## 3. The cache, serve-stale, prefetch and the flush

### 3.1 Entries and bounds

The cache (plan section 2.8, DNS-23) is per node and per view: its key is the view, the name, the type, the class and the DO and CD bits of the question, so split horizon never leaks through the cache and a client that asks without DNSSEC never gets the signatures another asked for. An entry is the upstream's answer in wire form without its OPT record, with the positions of its TTLs:

| Answer | Cached for |
|---|---|
| NOERROR with records | The smallest TTL of its records, at most `max_ttl_secs` (one day) |
| NXDOMAIN, or NOERROR without answer records (NODATA), with an SOA in the authority section | The smaller of the SOA's TTL and its MINIMUM (RFC 2308), at most `negative_ttl_secs` (one hour) |
| A negative answer without an SOA, SERVFAIL, REFUSED, any other RCODE, a truncated answer, an answer with TSIG, a TTL of 0 | Not cached |

The cache holds at most `entries` entries (10,000 under the Home profile, 100,000 under the others) and `max_bytes` octets of keys, answers and bookkeeping (16 MiB and 128 MiB). It is split into up to 64 shards by a hash of the key, each with its share of both bounds and its own least-recently-used list: a new entry that does not fit pushes out the least recently used of its shard, so the cache never holds more than `entries` entries. The octet figure counts the stored octets and the fixed size of each slot and map entry; the allocator's overhead comes on top (M24 measures the process).

### 3.2 A hit

A hit is answered on the query path, in the worker's buffer: the client's id and its question as it was sent (its case), QR and RA, the client's RD and CD, AA and AD clear, the records with each TTL lowered by the entry's age (and never above the entry's lifetime), and an OPT record with the server's EDNS size, the DO bit and the client's cookie when the client sent EDNS. An answer longer than the client's limit (512 octets without EDNS, else its size up to `edns.udp_size`; 65,535 on TCP) is the header and the question with TC, so that the client asks again over TCP.

The cost of a hit: building the key on the stack (at most 277 octets), one hash, a shard lock held for the lookup and the copy, the copy of the stored answer into the answer buffer and the rewrite of its TTLs, and one relaxed atomic add for the hit counter. Nothing is allocated. The query log records a hit with `cached: true`.

### 3.3 Serve-stale (RFC 8767)

An expired entry stays in the cache for `stale_secs` (one day) after it expired. When a query for it reaches the forwarder:

- if every upstream of its route is in back-off, the stale entry answers at once;
- else the upstream is asked, and when no answer has come after `stale_answer_ms` (1,800 ms, the client response timer RFC 8767 suggests), or the upstreams fail, the stale entry answers;
- a stale answer carries a TTL of 30 seconds on every record (RFC 8767 section 4), is counted in `tenko_dns_cache_stale_total` and logged with `cached: true`;
- the upstream query goes on in the background when the stale answer was sent for slowness, and its answer refreshes the entry.

Without a stale entry the client waits for the whole budget of the upstreams and gets SERVFAIL when none answers. Housekeeping removes the entries whose stale window has passed every minute; the bound holds without it.

### 3.4 Prefetch

When a hit finds an entry with less than a tenth of its lifetime left that has been asked before (the query that filled it and at least one hit), and the entry lives at least 10 seconds, its key is queued once; every 200 ms the forwarder asks the upstream again for the queued keys, through the rule that covers the name now, and the answer replaces the entry before it expires. A failed prefetch lets the next hit queue the entry again. The queue holds 1,024 keys; more are dropped (the entry is asked again when it expires). `prefetch = false` turns it off.

### 3.5 The flush

`POST /api/v1/nodes/{id}/dns/cache/flush` (scope `dns.write`) empties the node's cache, or with `?suffix=example.test` the entries whose name is at or below the suffix, in every view. It is the node command `dns.cache.flush` (arguments: an optional `suffix`), recorded as a row of `cluster.node_commands` and audited as `dns.cache.flush`; the detail says how many entries went. A suffix that is not a DNS name is 400 `sys.invalid_value`. A rule change does not flush: entries live out their TTL.

### 3.6 Figures

| Where | What |
|---|---|
| `GET /api/v1/nodes/{id}/dns` | `cache_entries`, `cache_bytes`, `cache_hits`, `cache_misses`, `cache_hit_ratio` (0 to 1, absent before the first lookup), `cache_stale`, and `problems` (stub zones and recursion lists) |
| `dns.stats` | The forwarder's counts: answered, failed, timed out, dropped, refused, hits, misses, stale, prefetched |
| Metrics | `tenko_dns_cache_hits_total{view}`, `tenko_dns_cache_misses_total{view}`, `tenko_dns_cache_stale_total`, `tenko_dns_cache_entries` ([observability.md](observability.md)) |

M24 (`bench/phase2-dns/results/`, the `m24-cache` file) measures the hit ratio, the latency and the memory at the bound, and serve-stale under an upstream cut.

## 4. Upstreams: the pool, the transports, TLS, 0x20 and the settings

### 4.1 The pool

The upstreams of one route (a rule, a stub zone, the default forwarder) form a set whose state lives as long as the route's upstreams do not change:

- **Choice.** Each attempt of a query goes to an upstream it has not tried: the healthy one with the lowest smoothed round-trip time (an upstream never measured counts as the fastest, so it is measured first), except one attempt in 16 that goes to another healthy upstream at random, so the times of the others stay current. When every upstream left is in back-off, the one whose back-off ends first is asked.
- **Health.** Three failures in a row (timeouts, refused connections, malformed answers) put an upstream in back-off for one second, doubling with each further failure up to a minute; an answer ends it. A failure also doubles its smoothed time, so a failing upstream is asked mostly by the probes.
- **Budget.** A query has `forward_retries + 1` attempts (3) of `forward_timeout_ms` each (2,000 ms). An answer with SERVFAIL or REFUSED moves on to the next upstream while attempts remain and is relayed when nothing better comes; a set of one upstream asks it again.
- **Status.** The counters per rule and upstream are the metrics of section 4.6.

### 4.2 The transports

| Transport | How |
|---|---|
| `plain` | UDP from a socket of the outgoing set (section 4.4), and the same query again over TCP when the answer is truncated; `transport = "tcp"` in the configuration asks over TCP only |
| `dot` | DNS over TLS (RFC 7858): TLS to port 853, ALPN `dot`, length-prefixed messages. Up to four idle connections per upstream are kept for 10 seconds for the next queries; a connection the server closed meanwhile costs one retry on a new connection. TLS sessions resume from the client configuration's session store |
| `doh` | DNS over HTTPS (RFC 8484): `POST` of `application/dns-message` to the upstream's path (`/dns-query` by default) over one HTTP/2 connection (ALPN `h2`) that every query to the upstream shares, opened again when the server closes it or an exchange times out (a cut network sends no reset); the query id is 0 (RFC 8484 section 4.1). An answer with another HTTP status than 200 counts as malformed |

TGL-14 asks for DoT or DoH towards upstreams where they support it. No upstream is built in (P2-Q5): the operator chooses the resolvers. Well-known public resolvers that offer both are, for example, Quad9 (`dns.quad9.net`, 9.9.9.9), Cloudflare (`cloudflare-dns.com`, 1.1.1.1) and Google Public DNS (`dns.google`, 8.8.8.8); a DoT rule names their certificate name in `tls_name`. A plain-text fallback is not automatic: a rule names one transport, and a second rule with another transport is a choice the operator makes.

### 4.3 TLS

The DoT and DoH clients use rustls with aws-lc-rs, as the rest of the process, TLS 1.2 and 1.3. The upstream's certificate must chain to a root of the system's store (read once, when the first DoT or DoH upstream is used), or, when `[dns] upstream_ca` names a PEM file, to a certificate of that file alone: a private CA replaces the system's roots rather than joining them, so a lab or an internal resolver cannot be impersonated by a public certificate. The name checked is the rule's `tls_name` (a DNS name or an IP address). A rule whose TLS cannot be set up (no root, a bad CA file, an invalid name) answers SERVFAIL and logs why.

### 4.4 Outgoing queries (DNS-08)

- **The query** is built anew for each attempt: a random id (from the system generator), the client's question, RD set and CD copied from the client, and an OPT record of 1,232 octets with the client's DO bit. The client's own options, its cookie among them, stay between the client and the node.
- **Source ports.** A UDP query leaves from a socket bound to a random port above 1023 that it holds alone for the exchange. Idle sockets are kept per address family (up to 64) and reused, each for at most 64 queries and one minute, so the ports keep changing without a socket per query; a socket whose exchange timed out is closed. A query to an upstream on a loopback address leaves from that address, from a set of sockets of its own.
- **0x20.** Plain upstreams get the question with each letter in a random case. The answer must carry the id, QR, opcode QUERY and the question in exactly the case it was sent; an answer in another case is not used, and after two such answers the upstream is asked in lower case from then on (logged once; `lower_case` in its state). DoT and DoH upstreams are asked in lower case: TLS already defeats spoofing.
- **The answer** is relayed with the client's id, its question as it was sent and this node's OPT record; AA and AD are cleared.

### 4.5 Settings

The `[dns]` keys of the resolver side ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)); the rest of `[dns]` is in [dns.md](dns.md) section 8. They are read at start; a change needs a restart of the node. The rules, stub zones and access lists are rows of the store and need none.

| Key | Default | Meaning |
|---|---|---|
| `forwarders` | none | The default forwarder: addresses, or tables `{ address, port, transport, tls_name, path }` with `transport` `udp`, `tcp`, `dot` or `doh` (section 2.1) |
| `forward_timeout_ms` | 2000 | Milliseconds one attempt has, 100 to 30,000 |
| `forward_retries` | 2 | Attempts after the first, 0 to 5 |
| `upstream_ca` | none | A PEM file of CA certificates for DoT and DoH upstreams, instead of the system's roots |
| `cache.enabled` | `true` | Keep a cache |
| `cache.entries` | 10,000 (Home), 100,000 | Entries at most, 1 to 10,000,000 |
| `cache.max_bytes` | 16 MiB (Home), 128 MiB | Octets at most, 64 KiB to 16 GiB |
| `cache.stale_secs` | 86400 | The stale window, 0 to 604,800 (0: no serve-stale) |
| `cache.stale_answer_ms` | 1800 | The wait before a stale answer, 100 to 30,000 |
| `cache.max_ttl_secs` | 86400 | The longest positive lifetime, 1 to 604,800 |
| `cache.negative_ttl_secs` | 3600 | The longest negative lifetime, 0 to 86,400 (0: no negative entries) |
| `cache.prefetch` | `true` | Prefetch popular entries |

### 4.6 Metrics

| Family | Labels | What |
|---|---|---|
| `tenko_dns_upstream_queries_total` | `rule` (the suffix, `default`, `stub:<zone>` or `stub-source:<zone>`), `upstream` (`address:port`), `transport` (`plain`, `dot`, `doh`), `outcome` (`ok`, `servfail`, `timeout`, `unreachable`, `malformed`) | Every exchange with an upstream; `servfail` is an answer with SERVFAIL or REFUSED that moved on to the next upstream, `malformed` includes the answers that broke the 0x20 case |
| `tenko_dns_upstream_rtt_seconds` | `upstream` | The round-trip time of the answered exchanges (50 µs to 2 s), summed over the rules that share an upstream |

The series of an upstream appear with its first exchange and stay for the life of the process.

## 5. Response policy zones and block lists

(WP5.2.)

## 6. Rate limiting

(WP5.2.)

## 7. DoT and DoH served to clients

(WP5.3.)

## 8. The query log and dnstap

(WP5.4.)

## 9. The home cut-over

(WP5.6.)
