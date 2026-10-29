# DNS: the resolver side

- Scope: how a node answers names outside the zones it serves: the forwarder, its rules and stub zones, the recursion access lists, the cache with serve-stale and prefetch, the upstreams over plain DNS, DNS over TLS and DNS over HTTPS, RPZ zones and block lists, and rate limiting (Phase 2, plan section 2.8; DNS-02, DNS-08, DNS-15, DNS-17, DNS-21, DNS-23, TGL-11, TGL-14, TGL-22), and, since Slice 10, Tenko's own recursive resolver that asks the root servers and the authorities itself (section 10; DNS-03, DNS-08, DNS-21). For operators who make a node the resolver of their clients, and for the builders of the later Phase 2 packages.
- The authoritative side (zones, records, the `dns` role, the engine) is [dns.md](dns.md); the contracts are [dns-contracts.md](dns-contracts.md). The code is `crates/tenko-dns` (`forward`, `cache`, `pool`, `upstream`, `outbound`, `forwarders`; the policy and the limits in `policy`, `lists`, `rate`; the recursive resolver in `recurse` and `infra`).

Contents:

1. [The resolver side and the lookup order](#1-the-resolver-side-and-the-lookup-order)
2. [Forwarding rules, stub zones and the recursion access list](#2-forwarding-rules-stub-zones-and-the-recursion-access-list)
3. [The cache, serve-stale, prefetch, the flush and the listing](#3-the-cache-serve-stale-prefetch-the-flush-and-the-listing)
4. [Upstreams: the pool, the transports, TLS, 0x20 and the settings](#4-upstreams-the-pool-the-transports-tls-0x20-and-the-settings)
5. [Response policy zones and block lists](#5-response-policy-zones-and-block-lists) (WP5.2)
6. [Rate limiting](#6-rate-limiting) (WP5.2)
7. [DoT and DoH served to clients](#7-dot-and-doh-served-to-clients) (WP5.3)
8. [The query log and dnstap](#8-the-query-log-and-dnstap) (WP5.4)
9. [The home cut-over](#9-the-home-cut-over) (WP5.6), with the recursion variant in 9.7
10. [Recursion](#10-recursion) (Slice 10, WP10.1)

## 1. The resolver side and the lookup order

A node with the `dns` role answers from its zones first and forwards the rest: Tenko has no recursive resolver of its own in Phase 2 (DNS-03 is Phase 5), so recursion is forwarding to upstream resolvers with a cache in front (DNS-02). One query goes through these steps, in this order (plan sections 2.2 and 2.3):

| Step | Where | What |
|---|---|---|
| 1. Header, rate limiter, view | `authoritative` | As for every query ([dns.md](dns.md) section 12.4): the opcode, the class, the meta types, the rate limiter's admission, then the view whose rules match first, else the implicit default view |
| 2. Zones | `authoritative` | A name in a primary or secondary zone is answered from the index, whatever the client asked for; stub and forward zones are not answered from |
| 3. Policy | `authoritative` (`PolicyEngine`) | Outside the zones the policy decides first: exemptions and allow lists, the RPZ zones, the block lists; a blocked name is answered here with the extended error "Blocked", and the answer of a name that passed is looked at again in steps 7 and 8 (section 5) |
| 4. Recursion desired | `authoritative` | A query without RD gets REFUSED with the extended error "Not Authoritative" (20) |
| 5. Recursion check | `forward` (on the query path) | The view's recursion access list, or the profile's default (section 2.3); a client that may not recurse gets REFUSED with the extended error "Prohibited" (18) |
| 6. A route | `forward` (on the query path) | A forwarding rule, a stub zone or the default forwarder covers the name, else REFUSED with "Not Authoritative" |
| 7. The cache | `cache` (on the query path) | A fresh entry answers at once, with the TTLs lowered by the entry's age (section 3) |
| 8. The upstreams | `forward`, `pool`, `upstream` (off the query path) | The query is copied and handed to the forwarder, which asks the route's upstreams, fills the cache, answers stale when the upstreams fail (section 3.3) and answers the client through the transport's reply path |

Steps 1 to 7 run on the worker that received the query and allocate nothing (ADR 0009; `crates/tenko-dns/tests/alloc.rs` runs cache hits in a view with a recursion access list, refused queries, and blocked names, rewritten cache hits and a rate-limited flood with the policy and the limiter installed, through the counting allocator). Step 8 runs on the tokio runtime, up to 1,024 queries at once, from a queue of 4,096; a full queue drops the query and the client retries.

Since Slice 10 a node can also resolve names itself: the forwarder starts the recursive resolver, steps 6 and 8 gain a route to it, and a name that no rule and no stub zone covers is recursed by default (section 10.1). The rest of this section describes the forwarder, which that route sits beside.

Every name outside the zones reaches the forwarder, which decides; so a node sets RA in every answer. The forwarded answers are counted in `tenko_dns_queries_total` with the RCODE relayed and timed from the hand-over to the answer; cache hits are counted and timed as any answer of the query path.

What is not in Phase 2: DNSSEC validation (the DO and CD bits go upstream and the signatures come back to a client that asked with DO, but AD is always clear), a recursive resolver of Tenko's own, aggressive use of NSEC (RFC 8198), and the client-subnet option (RFC 7871). Slice 10 adds the recursive resolver (section 10); validation and aggressive use of NSEC follow in later packages of that slice (section 10.16).

## 2. Forwarding rules, stub zones and the recursion access list

### 2.1 Forwarding rules

A forwarding rule (`dns.forwarders`, DNS-02) sends the names at or below its suffix to its upstreams: 1 to 16 addresses, each with an optional port and, for DoH, an optional path, all over one transport (`plain`, `dot` or `doh`; DoT and DoH need `tls_name`, the name in the upstreams' certificates). A rule applies in one view or in all views; there is one rule per suffix and view.

The rule for a name is the one with the longest suffix; at the same length a rule of the query's view goes before a rule of all views. The root suffix `.` covers every name: a root rule is the default forwarder of the store, and it wins over `[dns] forwarders` of the configuration file, which applies only when no rule of the store covers a name. A node needs neither: with no rule, no stub zone and no configured upstream, names outside the zones are refused.

| Route | Operation | Scope |
|---|---|---|
| `GET /api/v1/dns/forwarders` | `list_dns_forwarders` | `dns.read`: the rules by suffix, the root first; paged with `cursor` and `limit` |
| `POST /api/v1/dns/forwarders` | `create_dns_forwarder` | `dns.write`: `suffix`, `upstreams[]` (`address`, `port`, `path`), `transport`, `tls_name`, `view`, `description`, `mode` (`forward`, the default, or `recurse`), `validate` (default `true`) |
| `GET /api/v1/dns/forwarders/{id}` | `get_dns_forwarder` | `dns.read`, with the `ETag` of the row |
| `PATCH /api/v1/dns/forwarders/{id}` | `update_dns_forwarder` | `dns.write`, `If-Match` optional; an empty `tls_name` or `description` clears it, `all_views: true` makes the rule apply in every view |
| `DELETE /api/v1/dns/forwarders/{id}` | `delete_dns_forwarder` | `dns.write`, `If-Match` optional |

A rule of mode `recurse` names no upstream: the names under its suffix are resolved from the root servers (section 10), so a root rule that forwards can have a recursing exception for one suffix, and the other way round. `validate: false` relays a forwarding rule's answers unvalidated, the escape hatch for an upstream that strips the DNSSEC signatures (`docs/dnssec.md` section 12); a recurse rule always validates. Turning a rule to `recurse` drops its upstreams in the same change (`upstreams: []`, `tls_name: ""`, `transport: plain`).

Errors: `dns.forwarder.invalid` (400, parameters `field` and `reason`: no upstream or more than 16 on a forwarding rule, a DoT or DoH rule without `tls_name`, a path on a plain or DoT upstream or one that does not start with `/`, port 0, a view that does not exist, a second rule for the same suffix and view; a recurse rule with upstreams, a transport other than plain, a `tls_name` or `validate: false`), `dns.forwarder.not_found` (404), 412 for a stale `If-Match`. Each change is an inline job with its audit record (`dns.forwarder.create`, `dns.forwarder.update`, `dns.forwarder.delete`, the suffix in the context). The role's catalog follows the rows through the feed: a change answers queries from the next revision the node applies, with no restart.

The command line: `tenko dns forwarder list|create|get|update|delete`. A rule is named by its identifier or its suffix (when one rule has it):

```sh
tenko dns forwarder create . --upstream 192.0.2.1 --upstream 192.0.2.2
tenko dns forwarder create example.net --transport dot --tls-name resolver.example.net \
  --upstream 198.51.100.53 --upstream '[2001:db8::53]:853'
tenko dns forwarder create corp.example.test --transport doh --tls-name dns.example.test \
  --upstream 192.0.2.80:443/dns-query
tenko dns forwarder update example.net --all-views
tenko dns forwarder create corp.example.test --recurse
tenko dns forwarder delete corp.example.test
```

**The forwarders page** (`/dns/forwarders`) lists the rules by suffix with the root rule first; a recurse rule shows **Recurse** in place of a transport and upstreams, a forwarding rule whose answers are not validated is marked so. The rule editor chooses the mode (**Forward to upstream resolvers** or **Resolve from the root servers**); for forwarding it takes the transport, the upstreams, the TLS name and the **Validate the answers with DNSSEC** switch. The preset **Forward everything to a DoT resolver** opens the root rule (or a new one) over DoT, with the well-known resolvers of section 4.2 as buttons to fill it and the privacy sentence beside it: recursion asks each zone's authorities, each of which sees only its own names, forwarding sends every name to one resolver, and DoT protects the path to that resolver, not what it sees. Below the rules, **Default resolution** shows how each view resolves the names no zone and no rule covers: recurse, forward to `[dns] forwarders`, refuse, or the profile's default (recurse under every profile, REC-Q2), which is shown beside it; the implicit default view follows the profile. Each view's choice is stored as its `resolution` (`PATCH /api/v1/dns/views/{id}` with `resolution`, or `default_resolution: true`; the view's answer carries `profile_resolution`), and on the command line `tenko dns view update <name> --resolution recurse|forward|refuse|default`. A root rule covers every name of its views, so there the default resolution is never reached, which the block says.

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

## 3. The cache, serve-stale, prefetch, the flush and the listing

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

### 3.7 The listing

`GET /api/v1/nodes/{id}/dns/cache` (scope `dns.read` and read on the node) shows what the node's cache holds, as the cache view of Windows DNS and `rndc dumpdb -cache` do. It is the node command `dns.cache.list` (arguments: `suffix`, `view`, `limit`, `cursor`), which the role executes on the node that holds the cache; in Phase 2 that is the controller's own process.

| Parameter | Meaning |
|---|---|
| `suffix` | The name and the names under it, as the flush takes it: `example.test` finds `www.example.test`, not `badexample.test` |
| `view` | One view: its identifier, or `default` for the entries asked outside any view; every view when absent |
| `limit` | Entries per page, 1 to 1,000 (default 200) |
| `cursor` | The `next_cursor` of the previous page; absent for the first entry |

The entries come in the canonical order of their names (RFC 4034 section 6.1: label by label from the root, so `example.net` comes before `example.test` and `example.test` before `www.example.test`), then by type, by view (the default view first) and by the DO and CD bits the entry was asked with. Each entry has the name and type asked, the view, the RCODE of the answer (0, or 3 for NXDOMAIN), `ttl`, the seconds it stays fresh (0 once it is stale), `stale` for an expired entry within the stale window that answers only while the upstreams fail, `hits`, the answers it gave since it was stored, `dnssec_ok` and `checking_disabled`, and `records`, the records of the answer section in the typed form of the zone API (a CNAME chain shows the CNAME and the records of its target; a negative answer has none). An entry past its stale window waits for housekeeping and is not listed. A malformed suffix, view, limit or cursor answers 400 `sys.invalid_value` with the field; a node without a cache answers an empty page.

**The query path.** A page is chosen in two steps, so that a listing never holds a shard longer than a flush does: each shard is locked in turn, one at a time, for one pass over its map that keeps the keys of the `limit + 1` first entries after the cursor in a heap reserved before the first lock (the pass allocates nothing under the lock); then each chosen entry is copied under its shard's lock, one lookup each, and its records are decoded with no lock held. Every page is a new pass: an entry stored while the pages are read appears when it sorts after the cursor, one that went is left out, and none is listed twice.

**Audit.** The entries are the names the clients of the node asked, personal data as the query log is (section 8.6), so every page read is recorded as a row of `cluster.node_commands` and audited as `dns.cache.read` in the same write, with the principal, the node, the cursor range (`from_cursor`, `to_cursor`), the number of entries and the filters (`filter.suffix`, `filter.view`).

The **Cache** tab of the DNS page (`/dns/cache`), the rightmost tab beside the query log, shows **What the cache holds**, laid out as the cache view of the Windows DNS manager. It shares the node choice with the query log tab, so moving between the two keeps the node. It reads nothing until asked: **Show the entries** (then **Read again**) reads the entries at or below the name in the suffix field, 1,000 a page following the cursor until the last page or for at most ten pages; past the cap it stops and says that the view holds the first 10,000 entries and that a suffix narrows it. That press, and the reload after a flush, are the only reads: the tab never polls, never refreshes on focus and never reads when a folder is expanded or selected, since every page read is audited. Each read builds the tree anew. The left pane is the tree of names, one folder per label from **(root)** down (`www.example.test` is root, `test`, `example`, `www`); a folder is the root, a name with names under it, or the suffix read. The root starts expanded to the top-level domains and everything under it collapsed; with a suffix the path to it is expanded and its folder selected. The tree follows the WAI-ARIA tree pattern (Up and Down move and select, Right and Left open and close, Home and End). The right pane lists the folder selected: the folders under it first (a double click or Enter opens one), then its own entries named **(same as parent folder)**, then the entries of the names under it by their label, with the type, TTL left, view, validation state (with the extended error of a bogus entry), stale flag, hits and data; when every entry of the folder has the same validation state (two entries or more), the column header says it once (**State · all insecure**) and the rows carry no badge, and the stale flag stays on its row since it varies; the data is the records of the entry's type and its CNAME chain, an HTTPS or SVCB record in the presentation format of RFC 9460 (`1 . alpn=h2,h3 ipv4hint=192.0.2.10`: the priority, the target and the parameters in key order, an unknown key as `key65280=...`), and each RRSIG of the answer is a row of its own under the same name, summarised as the type covered, the signer and the expiry in UTC (`A, signer example.test, expires 2026-11-12 02:08`). The tree shows 200 folders under a folder and the pane 200 rows at a time, each with a button for more, so a folder with tens of thousands of names never puts them all in the page. With a suffix applied a **Flush** button runs the flush of section 3.5 for it after a confirmation and reads again. On the command line:

```text
tenko dns cache list <node> [--suffix example.test] [--view default] [--limit 200] [--cursor <cursor>]
tenko dns cache flush <node> [--suffix example.test]
```

## 4. Upstreams: the pool, the transports, TLS, 0x20 and the settings

### 4.1 The pool

The upstreams of one route (a rule, a stub zone, the default forwarder) form a set whose state lives as long as the route's upstreams do not change:

- **Choice.** Each attempt of a query goes to an upstream it has not tried: the healthy one with the lowest smoothed round-trip time (an upstream never measured counts as the fastest, so it is measured first), except one attempt in 16 that goes to another healthy upstream at random, so the times of the others stay current. When every upstream left is in back-off, the one whose back-off ends first is asked.
- **Health.** Three failures in a row (timeouts, refused connections, malformed answers) put an upstream in back-off for one second, doubling with each further failure up to a minute; an answer ends it. A failure also doubles its smoothed time, so a failing upstream is asked mostly by the probes.
- **Budget.** A query has `forward_retries + 1` attempts (3) of `forward_timeout_ms` each (2,000 ms). An answer with SERVFAIL or REFUSED moves on to the next upstream while attempts remain and is relayed when nothing better comes; a set of one upstream asks it again.
- **Status.** The counters per rule and upstream are the metrics of section 4.6; the times and states the choice works with are the figures of section 4.7.

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
| `forwarders` | none | The default forwarder: addresses, or tables `{ address, port, transport, tls_name, path }` with `transport` `udp`, `tcp`, `dot` or `doh` (section 2.1). With the recursive resolver on, it serves only where a view says `forward` (section 10.1); to forward everything, add a root rule or switch the resolver off |
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
| `tenko_dns_upstream_rtt_seconds` | `rule`, `upstream` | The round-trip time of the answered exchanges (50 µs to 2 s) per rule and upstream (until the visibility package: by upstream alone) |
| `tenko_dns_upstream_health` | `rule`, `upstream` | A gauge computed at the scrape: 1 while the upstream answers, 0.5 while it fails without being in back-off, 0 in back-off |

The series of an upstream appear with its first exchange; the counters and the histogram stay for the life of the process, the health gauge leaves with the last set that holds the upstream (a rule deleted or its upstreams changed).

### 4.7 Response times and health

The pool keeps per upstream of every set what its choice works with, and the node shows it (the owner's test-drive backlog of 2026-10-18):

| Figure | What |
|---|---|
| `last_rtt_ms` | The round-trip time of the last answer |
| `ewma_ms` | The smoothed round-trip time the choice uses: an exponentially weighted mean with weight 1/8 per answer, doubled by each failure (at least 1 ms, at most the attempt's timeout) |
| `p50_ms`, `p99_ms` | The median and the 99th percentile of the answers of the last minute (at most the last 512, so above about 8 answers a second the window is shorter than a minute), with `window_answers` |
| `state` | `unknown` (not asked yet), `up` (the last exchange was answered), `degraded` (failing, fewer than three times in a row), `down` (in back-off) |
| `chosen` | The upstream the next query of the route goes to outside the probes: the healthy one with the lowest smoothed time, else the one whose back-off ends first |
| `failures`, `answered`, `failed` | Failures in a row; answered and failed exchanges since the role started |
| `last_error`, `last_error_at` | The last failure in English (a timeout, an unreachable upstream, a malformed answer or one that broke the 0x20 case) and when |

They are kept on the reply path, under the locks the pool already takes there (a ring of 512 times per upstream, no allocation per answer), and computed when they are read; the query path does not see them. They are figures of the node that answers and start empty when its role starts.

- **Node status.** `GET /api/v1/nodes/{id}/dns` lists `upstreams: [{ rule, stub, label, upstreams: [...] }]`: the default forwarder of `[dns] forwarders` (no `rule`), every forwarding rule by suffix (with its id; an upstream not asked yet is `unknown`), and the stub zones whose name servers were learnt.
- **Forwarding rules.** `GET /api/v1/dns/forwarders` and `GET /api/v1/dns/forwarders/{id}` carry `upstream_status` per rule, in the order of its `upstreams`, when the server runs the DNS role. The forwarders page shows each upstream with a dot for its state, its median time and the tag Next on the chosen one; the title holds every figure and the last error.
- **The node's DNS settings page** (`/settings/dns`) has the section Upstreams: a row per upstream with the rule, the state, the four times, the counts and the last error.
- **The command line.** `tenko dns forwarder list` prints a row per upstream: `STATE` (with `*` on the chosen one), `RTT` (the last), `EWMA`, `P50` and `P99` in milliseconds; `-` where the server runs no DNS role or has not asked the upstream yet.
- **Metrics.** `tenko_dns_upstream_rtt_seconds{rule,upstream}` and `tenko_dns_upstream_health{rule,upstream}` (section 4.6).

## 5. Response policy zones and block lists

The policy blocks names for the clients of a node (DNS-21): response policy zones (RPZ) for threat feeds and the operator's own rules, and block lists in hosts-file and domain-list form for the Pi-hole style use at home. Both are rows of the store; the catalog of the role compiles them at the revision it serves, so a change reaches the query path through the feed like a zone change (plan sections 2.8 and 2.10). The code is `crates/tenko-dns/src/policy` (the engine), `src/lists` (the compiler, the rows, the compile job) and `crates/tenko/src/serve/lists.rs` (the fetcher and the leader service).

### 5.1 The order

The policy runs for every name outside the zones (step 3 of section 1), before the forwarder, in this order; the first that decides ends it:

1. **Exempt clients.** A client in the `exempt` prefixes of an enabled allow list is never blocked, by any list or RPZ zone.
2. **Allow lists.** A name on an enabled allow list, or below a name on it, is never blocked.
3. **RPZ zones**, in the view's order: the RPZ zones the view's scope map names, in that order, then the others by name (the implicit default view takes them all by name). In each zone the client-IP triggers, then the QNAME triggers; the first zone with a match decides, and a PASSTHRU match ends the policy for the query.
4. **Block lists**, the enabled ones by name: a name on a list or below a name on it is answered with the list's action, unless the list's `exempt` prefixes hold the client.

A query that passed is looked at again when its answer comes back from the cache or from an upstream (`tenko_dns::policy::answer`): the RPZ zones in the same order look at the CNAME targets of the answer (QNAME triggers), its A and AAAA records (response-IP triggers), the NS records of the answer or the authority section (NSDNAME triggers) and the addresses of those name servers in the additional section (NSIP triggers); then the block lists look at the CNAME targets, so that a tracker behind a CNAME of an allowed-looking name is blocked too. A CNAME target on an allow list is not blocked by name. A blocked answer is rewritten before it leaves: the header and question of the answer, the records of the action, and the answer's OPT record with the extended error. The answer of a cache hit is looked at on the query path without an allocation; the answer of an upstream on the runtime, before the client gets it.

### 5.2 RPZ zones

An RPZ zone is a zone of kind `rpz` ([dns.md](dns.md) section 1). In Phase 2 its records come from a zone file uploaded with the zone file import (`POST /dns/zones/{id}/records/import`) or from the API; zone transfers in are Slice 6. The owner names, relative to the zone's apex, are the triggers of draft-vixie-dnsop-dns-rpz, and the records at a trigger are its action. The default scope is read.

| Owner (relative to the apex) | Trigger |
|---|---|
| `bad.example.org` | QNAME: the query name, or a CNAME target of the answer, is `bad.example.org` |
| `*.bad.example.org` | QNAME: a name below `bad.example.org` (not the name itself); an exact trigger wins over a wildcard, a closer wildcard over one further up |
| `32.1.2.0.192.rpz-ip` | Response IP: an A record of the answer is 192.0.2.1; `24.0.2.0.192.rpz-ip` is 192.0.2.0/24; IPv6 groups are reversed with `zz` for the zero run (`48.zz.db8.2001.rpz-ip` is 2001:db8::/48); the longest prefix wins |
| `ns1.example.org.rpz-nsdname`, `*.example.org.rpz-nsdname` | NSDNAME: a name server of the answer is that name, or below it |
| `32.53.2.0.192.rpz-nsip` | NSIP: an address of a name server in the additional section is in the prefix |
| `32.10.113.0.203.rpz-client-ip` | Client IP: the client's address is in the prefix |

| Records | Action |
|---|---|
| `CNAME .` | NXDOMAIN |
| `CNAME *.` | NODATA (NOERROR, no records) |
| `CNAME rpz-passthru.` | PASSTHRU: not rewritten, by this zone or any after it (an exemption) |
| `CNAME rpz-drop.` | DROP: no answer at all |
| `CNAME rpz-tcp-only.` | Over UDP an empty answer with TC, so the client asks again over TCP; over TCP the real answer |
| any other records | Local data: the records of the type asked (or a CNAME, for any type) instead of the real answer; NODATA when none fits |

An owner that is no valid trigger (an address label out of range, an unknown prefix length) is skipped and logged when the zone is compiled. What a forwarding resolver cannot see is not matched: the NSDNAME and NSIP triggers look only at the NS records and addresses that the upstream's answer carries (most recursive resolvers send none with a positive answer), and a forwarder does not resolve the name servers of a name to find them. The recursive resolver of section 10 knows the delegation it followed and puts it into its answers while an RPZ zone has such triggers, so that they match (section 10.11).

### 5.3 Block lists and allow lists

A list (`dns.lists`) has a unique name, a kind (`block`, the default, or `allow`), a source (a URL fetched on its interval, or an uploaded file), a format (`hosts` or `domains`), an interval of 1 to 168 hours (24 by default), an action for its names (`nxdomain`, the default, `nodata`, or `redirect` with an address, answered for A or AAAA as the address is and NODATA for the other type, TTL 60), up to 1,000 `exempt` client prefixes, a switch and a description. Every list matches its names and every name below them: `example.org` on a list blocks `ads.example.org` as well. The `exempt` prefixes of a block list skip that list; the `exempt` prefixes of an allow list skip the whole policy, so an allow list with no names and some prefixes is the per-client exemption of a node. A change of a list's source or format drops its versions: the list serves nothing until its next fetch or upload.

The formats, as the compiler reads them (`crates/tenko-dns/src/lists/compile.rs`):

- `#` starts a comment anywhere on a line, `!` at the start of a line too; blank lines and CRLF line ends are fine.
- A hosts file has an address and one or more names on a line (`0.0.0.0 ads.example.org`, `127.0.0.1 a.example.org b.example.org`); the address is ignored, and the boilerplate names (`localhost`, `localhost.localdomain`, `local`, `broadcasthost`, the `ip6-*` names) are skipped.
- A domain list has one name per line; a line in hosts form is read as one, and the Adblock forms `||name^` and `*.name` are read as `name`.
- Names are folded to lowercase; a label outside ASCII is lowercased and written in Punycode (`bücher.example.org` is `xn--bcher-kva.example.org`). A line that holds no valid name (a URL, a label over 63 octets, a name over 255) is counted and skipped, never an error.

Lists that work in these forms: the hosts files of the common ad and tracker list projects, Pi-hole's gravity sources, and domain lists of one name per line. Wildcard and regular-expression rules beyond `||name^` and `*.name` are not read. Pi-hole matches the names of a hosts file exactly; Tenko blocks the names below them as well.

### 5.4 Fetches, uploads and versions

Each list compiles to a version (`dns.list_versions`): the names as one sorted suffix set, its entry count, when the source was read and the source's HTTP entity tag. The compiled form is the keys of the names (their labels from the right, each with its length), sorted, duplicates and names below a listed name dropped, front-coded, and deflated above 64 KiB; a million random names take 10.8 MiB, one store value (at most 12 MiB; a larger list is refused with `dns.list.invalid` and keeps its version). Only the newest version is kept. The catalog builds the matcher of the query path from it: a hash of every listed name, computed label by label from the right, so a lookup probes once per label of the query name (M25, section 5.7).

- **The compile job** `dns.list.compile` has one step. For a URL list it sends `If-None-Match` with the entity tag of the newest version and reads at most `[dns.lists] max_download` MiB within `fetch_timeout_secs`; `304 Not Modified` ends the job without a write. The text is parsed and compiled, and the next version, the removal of the one before and the audit record `dns.list.compile` (with the entries and the skipped lines) commit with the step. A failure (the server unreachable, an HTTP error, a list too large) keeps the version the list has and is shown in the list's `last_error` (`dns.list.fetch_failed`, `dns.list.invalid`, `dns.list.upload_missing`) with `last_error_detail` and `last_checked`.
- **The leader service** `dns.lists` looks at the lists every minute and submits the job for every enabled URL list whose newest version and last attempt are older than its interval: a new list within a minute, a list whose last attempt failed again after 15 minutes (or its interval, when shorter). It runs on the leader only (P2-Q6), so one controller fetches for the installation and the nodes need no internet access; in Phase 5 the versions reach the nodes through node sync.
- **By hand**: `POST /dns/lists/{id}/fetch` submits the job of a URL list at once (audited `dns.list.fetch`); `PUT /dns/lists/{id}/file` hands in the file of an uploaded list as `text/plain`, at most `[dns.lists] max_upload` MiB (64 by default), and submits the job with the file as its source (audited `dns.list.upload`). Both answer 202 with the job (`GET /jobs/{id}`); a fetch of an uploaded list, or an upload to a URL list, is 409 `dns.list.invalid`.
- The command line: `tenko dns list list|create|get|update|delete|fetch|upload`.

The outcome of the last attempt (`last_error`, `last_checked`) is kept by the controller that ran the job; on the single node of Phase 2 that is the node itself, and the job record keeps every failure.

### 5.5 The answer

A blocked query is answered per its action with the extended error "Blocked" (RFC 8914, info code 15) in the OPT record, when the client sent EDNS: NXDOMAIN, NODATA, the redirect address, the local data, nothing (DROP), or an empty truncated answer (TCP-only over UDP). The query log records the answer as it leaves the query path; for a forwarded answer the policy rewrote, the log shows the upstream's RCODE (section 8).

### 5.6 Settings and status

`[dns.lists]` of `tenko.toml` sets the fetch: `fetch_timeout_secs` (60, 5 to 600), `max_download` (64 MiB, 1 to 1,024) and `max_upload` (64 MiB, 1 to 1,024). The lists and RPZ zones themselves are rows of the store and need no restart.

The node status (`GET /api/v1/nodes/{id}/dns`) lists `blocked: [{ "list": "<name>", "count": n }]`: the queries each enabled block list and each RPZ zone (under its zone name) blocked since the role started, by name. The command `dns.stats` reports the same counts in its detail. The metric `tenko_dns_blocked_total{list}` counts the same per list and zone name since the process started (section 6.4).

### 5.7 M25

`bench/phase2-dns/scripts/run-m25-lists.sh` runs the example `lists_bench` (the compiler and matcher the binary links) on a generated list of a million names: compile and matcher together in 1.0 s on Windows and 1.6 s with the static musl build on Linux (threshold 2 s), and a lookup in about 100 ns for a name of 2 labels, 160 ns for 4 and 250 ns for 8, so the cost per label does not grow with the labels or the list. The figures and the machine are in `bench/phase2-dns/results/2026-10-18-m25-lists.md`.

### 5.8 Blocking view

A page for the home use of the lists, available in every profile (the DNS area's tab Blocking, `/dns/blocking`): what the lists blocked, per list, client and hour, allow from the log, and a pause switch. It reads the node's query log (section 8 of this document and `docs/dns.md` section 8), so the log must be on (`[dns.log] enabled = true`; off by default under Home); the figures are those of the logged queries, so `[dns.log] sample` thins them as well.

- **The figures.** `GET /api/v1/dns/blocking/stats?window=24h|7d&top=N` issues the node command `dns.blocking.stats` on the node that answers: the queries of the last 24 hours or 7 days (as far as `[dns.log] days` keeps them), how many a block list blocked and how many the cache answered, the distinct clients, the queries and the blocked ones per hour, the blocked per list, the names blocked and asked most often, the clients that asked most often, and the newest 50 blocked queries. The log's `blocked` field names the list that blocked a query on the query path (the visibility package filled it; before, it stayed empty). A read looks at 512 MiB of log segments at most, newest first; a log that holds more in the window answers the newest part with `truncated`. The read is recorded as a node command and audited as `dns.blocking.stats` with the window, since the figures name the clients and what they asked. A client is shown as the log keeps it: its pseudonym of the day (`p:...`, so one client counts once per day), its address only to a principal that may update the node (with the DNS name IPAM records for the address, for a principal that may read addresses), or not at all with `client = "hidden"`. 409 `dns.blocking.log_off` while the log is off.
- **Allow from the log.** `POST /api/v1/dns/blocking/allow` with `{ "name", "list"? }` adds the name (and the names under it) to an uploaded allow list: the one named, or the list `allowed`, created the first time (an enabled allow list of domains). The names of the list's newest version are read back from its compiled form, the name is added, and the text goes to the compile job `dns.list.compile` as an upload would (202 with the job); a name the list covers already changes nothing (200, `already`). Audited as `dns.blocking.allow` with the name and the list, before the job's `dns.list.compile`. A URL list or a block list is refused with 409 `dns.list.invalid`.
- **The pause.** `POST /api/v1/dns/blocking/pause` with `{ "minutes" }` (1 to 1,440; the page offers 5, 15 and 60) or without them (until resumed) issues `dns.blocking.pause`; `DELETE /api/v1/dns/blocking/pause` issues `dns.blocking.resume`. While a pause lasts no block list blocks a name, in the query or in the answer; the allow lists, the exemptions and the RPZ zones apply as before. The pause ends by itself at its end: the query path reads one atomic while no pause is set and the clock only during one, so a pause costs nothing outside it. Each is recorded as a node command and audited as `dns.blocking.pause` (with the minutes) or `dns.blocking.resume`; the node status and the figures carry `blocking_paused: { since, until }`. The pause is a state of the node's process, not a job of the store: a restart ends it and the lists block again (registering a job step for it would need the start-up of `tenko serve`, which this package does not change).
- **The command line.** `tenko dns blocking stats [--window 24h|7d] [--top N]`, `tenko dns blocking pause [--minutes N]`, `tenko dns blocking resume`.
- **Limits.** A block found in an answer (a CNAME target on a list) is counted per list in `tenko_dns_blocked_total` but logged without the list, since the forwarder logs a forwarded answer before the policy looks at it (section 5.5). The figures are those of the node that answers; in Phase 5 a cluster reads them per node.
- **Next step.** Client groups with different lists, and the AdBlock Plus and regular-expression rule syntax, are not built: today a list applies to every client except the prefixes it exempts, and a list holds names in hosts-file or domain-list form only.

## 6. Rate limiting

Two limits protect a node and the networks around it (DNS-17, TGL-11), both in `crates/tenko-dns/src/rate` and called by the resolver: response rate limiting (RRL) against reflection attacks with spoofed sources, and a per-client query limit against a client that floods the node.

### 6.1 Response rate limiting

RRL works like BIND's. Identical responses to one client prefix (a /24 for IPv4 and a /56 for IPv6 by default) are counted: positive answers and NODATA by query name and type, NXDOMAIN and referrals by zone (so a flood of random names under one zone shares one count), errors by kind alone. Each count is a token bucket that fills at `responses_per_second` (`errors_per_second` for NXDOMAIN and errors) up to one second's worth and may run up to `window_secs` into debt; a response without a token is limited, and is debited as well, so a source that keeps asking above the rate gets only slips until it slows down for the window. Every `slip`-th limited response (2 by default) is sent as an empty answer with TC set, so that a real client whose address was spoofed asks again over TCP; the other limited responses are dropped.

RRL applies to the answers of the resolver (zones, policy answers, refusals) over UDP. TCP, DoT and DoH are not limited: their source cannot be spoofed. Forwarded answers are not limited either, since only clients the recursion access list allows get them (section 2.3). With `exempt_known` (the default) the clients in the prefixes IPAM knows and loopback are never limited, so a home network's own clients are untouched; `exempt` adds prefixes.

### 6.2 The per-client query limit

`client_qps` queries per second per client address (an IPv6 client by its /64) with a burst of `client_burst` above it; a query over the limit is dropped before the lookup. It applies to every transport. Exempt clients are not limited.

### 6.3 Settings and profiles

The keys of `[dns.limits]` ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)), read at start; the keys that are not set follow the security profile in force when the role starts (TGL-11):

| Key | Home and Standard | Hardened | Lab | Meaning |
|---|---|---|---|---|
| `rrl` | on | on | off | Response rate limiting |
| `responses_per_second` | 20 | 5 | (20) | Identical answers, NODATA and referrals per second per client prefix, 1 to 10,000 |
| `errors_per_second` | 10 | 5 | (10) | NXDOMAIN and errors per second per client prefix, 1 to 10,000 |
| `client_qps` | 0 (off) | 200 | 0 (off) | Queries per second per client, 0 to 100,000 |
| `client_burst` | | 400 | | The burst above `client_qps`; not set: twice `client_qps` |

The other keys are the same in every profile: `window_secs` (15, 1 to 3,600), `slip` (2, 0 to 10; 0 drops every limited response, 1 truncates every one), `ipv4_prefix` (24, 8 to 32), `ipv6_prefix` (56, 16 to 128), `exempt_known` (`true`), `exempt` (none, at most 1,000 prefixes) and `table` (65,536 slots per table, 1,024 to 16,777,216). TGL-11 puts RRL on under Home: with `exempt_known` it limits only sources outside the home's own prefixes.

The tables are fixed at start: a slot per key hash, sharded behind short locks, so the query path allocates nothing (`crates/tenko-dns/tests/alloc.rs` runs a limited flood with the policy installed). A new key takes over its slot with a full bucket; with 65,536 slots per table a flood from many sources may push out the bucket of another, which then starts full again.

### 6.4 Metrics

| Family | Labels | What |
|---|---|---|
| `tenko_dns_blocked_total` | `list` (a block list's name, an RPZ zone's name, `other` beyond 1,024 names) | Queries blocked by the policy, since the process started |
| `tenko_dns_rrl_dropped_total` | `kind` (`answer`, `nodata`, `nxdomain`, `referral`, `error`) | Responses RRL dropped |
| `tenko_dns_rrl_slipped_total` | | Responses RRL sent as an empty truncated answer |
| `tenko_dns_client_limited_total` | | Queries the per-client limit dropped |

The node status does not repeat the rate counters; `dns.stats` reports them in its detail.

## 7. DoT and DoH served to clients

This page describes how a node serves DNS over TLS and DNS over HTTPS to its clients (DNS-14, WP5.3 of the Phase 2 plan). The engine side is `tenko_dns::tls` (`crates/tenko-dns/src/tls`). The role side is the `[dns.tls]` section of `tenko.toml`, read by the `dns` role start (`crates/tenko/src/serve/dns.rs`). The deployment steps, including the HAProxy snippets, are in [`deploy/README.md`](../deploy/README.md), section "DNS over TLS and DNS over HTTPS".

### 7.1 The transports

Both transports are off by default. `[dns.tls] dot = true` and `doh = true` turn them on. They run on the tokio runtime beside TCP and call the same responder as UDP and TCP, so a query gets the same answer on every transport: the same views (a view can match on `transport` `dot` or `doh`), the same cookie secret, the same forwarder, the same query log and the same metrics, only with another `proto` label.

| Transport | Default address | Framing | ALPN |
|---|---|---|---|
| DoT (RFC 7858) | each `[dns] listen` address on port 853 | the two-octet length prefix of RFC 7766 inside TLS | `dot` |
| DoH (RFC 8484) | each `[dns] listen` address on port 443 | HTTP/2, or HTTP/1.1 for clients that ask for it | `h2`, `http/1.1` |

**DoT** reads messages in arrival order. A client may pipeline queries; queries that were already received are answered before anything is written. The answers go out together, and are flushed, when no further query is buffered or 32 KiB of answers are waiting. A forwarded query is answered when the upstream's answer arrives, out of order with the rest, as RFC 7766 allows. A client that offers ALPN without `dot` fails the handshake. A client that offers no ALPN at all is served.

**DoH** serves one path, `/dns-query`:

| Request | Answer |
|---|---|
| `GET /dns-query?dns=<base64url>` (no padding; padding, also percent-encoded, is accepted) | `200`, `application/dns-message` |
| `POST /dns-query` with `Content-Type: application/dns-message` and the message as the body | `200`, `application/dns-message` |
| another path | `404` |
| another method | `405` with `Allow: GET, POST` |
| `POST` with another media type | `415` |
| a body over 65,535 octets | `413` |
| a missing or undecodable `dns` parameter, a message shorter than a header, a response, or a query the resolver drops | `400` |
| a forwarded query whose answer does not come within 15 s | `504` |

A DNS answer is always `200`, whatever its RCODE (RFC 8484 section 4.2.1). Its `Cache-Control` is `max-age=` the smallest TTL of the answer and authority sections. A negative answer therefore carries the TTL of its SOA, which the resolver has already capped at the SOA minimum (RFC 2308). An answer without records gets `max-age=0`. The answer keeps the query's ID; clients that send ID 0, as RFC 8484 recommends, get 0 back. Nothing else of HTTP is used: no cookies, no redirects, no content negotiation (the `Accept` header is not read), no server push.

### 7.2 The TLS material

There is no ACME (owner decision P2-Q8). DoT and DoH serve one of four sources:

| Setting | Certificate served | Renewal or reload |
|---|---|---|
| `[tls] mode = "internal_ca"` (the default), no `[dns.tls] certificate` | The API's server certificate from the internal CA, for the installation's host name, `[tls] alt_names` and `[tls] addresses` | Renewed by the API's renewal task; DoT and DoH follow it |
| `[tls] mode = "imported"`, no `[dns.tls] certificate` | The API's imported files (`[tls] cert_path`, `key_path`) | The API's watcher reloads changed files every `[tls] watch_interval_secs`; DoT and DoH follow it |
| `[dns.tls] certificate` and `key` | A PEM chain and key for DNS only, for example a certificate whose name is the resolver's name (`dns.example.test`) rather than the console's | Watched in the same way, every `[tls] watch_interval_secs`; a file that fails to load keeps the previous certificate and logs a warning |
| `[dns.tls] behind_proxy = true` | None. The reverse proxy ends TLS | In the proxy |

Hot reload works without a restart: the listeners keep one TLS configuration over a certificate resolver that swaps its certificate in place. The next handshake gets the new certificate, the listener is never dropped, and connections that are already open finish on the certificate they started with (`crates/tenko-dns/tests/tls.rs`). TLS 1.3 is preferred. TLS 1.2 is allowed unless `[tls] tls13_only` is set or the profile is Hardened. TLS 1.3 sessions resume with tickets, so a reconnecting client saves a round trip (RFC 7858 section 3.4). There is no early data and no client authentication.

**Clients of the internal CA.** A client must trust the CA root (`<data_dir>/tls/ca-root.pem`, or `GET /api/v1/system/ca-root`) and must ask for a name that is on the certificate. With `kdig`: `kdig @192.0.2.53 +tls-ca=ca-root.pem +tls-hostname=tenko.example.test www.example.test`. Operating systems that take a DoT or DoH resolver by name (Android's private DNS, browsers) only accept a certificate from a CA they trust. For them, use the imported mode or `[dns.tls] certificate` with a certificate from a public CA, or install the root on every client.

**Behind a reverse proxy.** The proxy ends TLS. DoT then reaches Tenko as plain length-prefixed DNS (HAProxy in TCP mode) and DoH as plain HTTP (HAProxy as HTTPS). Both are served on the `dot_listen` and `doh_listen` addresses, which must be listed and must not be wildcards (loopback or an internal address). Only peers in `[tls] trusted_proxies` may connect; any other connection is closed at once and counted as refused. The client address, which the views, the query log and the per-client limits use, is found in this order:

1. With `[dns.tls] proxy_protocol = true`, every connection must start with a PROXY protocol version 2 header (`send-proxy-v2`). The header's source address is the client. A `LOCAL` header (the proxy's own health check) leaves the proxy as the client. A connection without a valid header is closed. Version 1 (the text form) is not read.
2. Without it, DoH takes the last entry of the last `X-Forwarded-For` header (`option forwardfor`).
3. Otherwise the client is the proxy.

### 7.3 Limits

Each transport counts its own connections, separately from TCP's. A burst of encrypted connections therefore cannot take TCP 53 away from plain clients, and plain clients cannot take the encrypted transports away either.

| Limit | Default | What happens |
|---|---|---|
| `max_connections` | 1,000 per node and transport | A connection over the cap is closed at accept and counted as refused |
| `per_client` | 10 per client address and transport | The same. Behind a proxy only the node cap applies, because every connection comes from the proxy |
| `handshake_timeout_secs` | 5 | A TLS handshake or PROXY header that fails or takes longer closes the connection; counted as a handshake failure |
| `idle_secs` | 30 | A DoT connection with no query for this long is closed with a TLS `close_notify`. A DoH connection with no request in progress for this long is closed: HTTP/2 `GOAWAY`, or the end of the HTTP/1.1 keep-alive |
| `doh_streams` | 100 | Concurrent requests on one HTTP/2 connection (`SETTINGS_MAX_CONCURRENT_STREAMS`) |
| fixed | 65,535 octets | The largest message on either transport |

When the server stops, it stops accepting. DoT connections close after the query in hand, and DoH connections get `GOAWAY` and have 2 seconds to finish their requests. Response rate limiting (TGL-11, RRL) and the per-client query limits of the rate limiter apply to the query, not to the transport, and are the same as on TCP.

**Allocation.** Once a DoT connection is up, a query allocates nothing: it runs on the runtime thread's buffers, the same as TCP. Each connection allocates its read buffer, its write buffer and the TLS state. A DoH request allocates its HTTP request and answer (hyper), the decoded query and a copy of the answer. The query path behind them is the allocation-free one that `tests/alloc.rs` checks.

### 7.4 Settings

The `[dns.tls]` section of `tenko.toml` ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)). Environment variables follow the usual pattern, for example `TENKO_DNS__TLS__DOT=true` and `TENKO_DNS__TLS__DOH_LISTEN=192.0.2.53:443`. `tenko config check` validates the section against the rest of the file. The settings are read at start; a change needs a restart.

| Key | Default | Meaning |
|---|---|---|
| `dot`, `doh` | `false` | Serve DoT, DoH |
| `dot_listen` | each `[dns] listen` address on 853 | DoT addresses |
| `doh_listen` | each `[dns] listen` address on 443 | DoH addresses |
| `certificate`, `key` | not set: the API's certificate | A PEM chain (leaf first) and key for DoT and DoH only; both or neither |
| `behind_proxy` | `false` | Plain DNS and HTTP from `[tls] trusted_proxies`, on listed non-wildcard addresses |
| `proxy_protocol` | `false` | With `behind_proxy`, every connection starts with a PROXY v2 header |
| `max_connections` | 1000 | 1 to 100,000 per node and transport |
| `per_client` | 10 | 1 to 1,000 per client address and transport |
| `idle_secs` | 30 | 1 to 3,600 |
| `handshake_timeout_secs` | 5 | 1 to 60 |
| `doh_streams` | 100 | 1 to 1,000 |

The configuration check refuses the following:

- a DoT or DoH address that takes the port of the API (`[server] listen`) or the TCP port of `[dns] listen`, or DoT and DoH on the same port. DoH on the API's own port and path is not served; give DoH its own address or port, or put both behind the proxy;
- `behind_proxy` without `[tls] trusted_proxies`, without listed addresses, or with a wildcard address;
- `behind_proxy` together with `certificate`, and `proxy_protocol` without `behind_proxy`;
- terminating TLS when the API has no certificate (`[tls] mode = "reverse_proxy"` or `"plain"`) and `[dns.tls] certificate` is not set.

A certificate that does not load fails the start with `start.dns.tls`. An address that cannot be bound fails it with `start.dns.bind`. Ports 853 and 443 are below 1024 and need `CAP_NET_BIND_SERVICE` on Linux, as port 53 does.

### 7.5 Status and metrics

`tenko serve` ends the role's line with the encrypted listeners, for example `dns role answering on 192.0.2.53:53 (UDP and TCP), ...; DoT on 192.0.2.53:853, DoH on 192.0.2.53:443 with the API's certificate (internal_ca)`. The node's status (`GET /api/v1/nodes/{id}/dns`, `listeners`) lists each DoT and DoH address with the transport `dot` or `doh`. `Server::layout` reports, for each transport, its addresses, its open connections, the refused ones and the failed handshakes (`tls` in the worker layout); the API route shows the TCP counters only so far.

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_dns_queries_total` | counter | `proto` = `dot`, `doh` (with `view`, `rcode`) | Queries answered, as on UDP and TCP |
| `tenko_dns_query_duration_seconds` | histogram | `proto` | Time from a query's arrival to its answer |
| `tenko_dns_connections` | gauge | `proto` | Open DoT and DoH connections |
| `tenko_dns_connections_refused_total` | counter | `proto` | Connections refused by a cap, or, behind a proxy, from an untrusted peer |
| `tenko_dns_tls_handshake_failures_total` | counter | `proto` | TLS handshakes and PROXY headers that failed or timed out |

The last three families are registered when DoT or DoH is on.

### 7.6 Conformance

| RFC | Behaviour | Status |
|---|---|---|
| RFC 7858 | DoT on port 853, length-prefixed messages, pipelining, idle close, connection reuse | Implemented |
| RFC 7858 section 3.4 | TLS session resumption | Implemented (TLS 1.3 tickets) |
| RFC 8310 | ALPN `dot` | Implemented |
| RFC 8484 | `GET` with `dns`, `POST` with `application/dns-message`, HTTP/2, HTTP freshness from the smallest TTL | Implemented |
| RFC 8484 section 5.1 | `max-age` for negative answers from the SOA | Implemented |
| RFC 7830, RFC 8467 | EDNS(0) padding of encrypted answers | Not done: the answers are not padded |
| RFC 9250 | DNS over QUIC | Not done |
| RFC 8484 section 5.2 | HTTP/2 server push | Not done (never used) |
| PROXY protocol | Version 2 header for the client address | Implemented; version 1 not read |

### 7.7 Known limits

- A change of the API's TLS mode while the process runs (the settings page switching to the reverse-proxy mode) removes the certificate that DoT and DoH share with the API, and their handshakes then fail until the node restarts with a matching `[dns.tls]`. A certificate of their own (`[dns.tls] certificate`) does not have this dependency.
- The API route of the node status shows the DoT and DoH listeners, but not yet their open and refused counters; `Server::layout` and the metrics have them.
- Answers are not padded (RFC 8467). A passive observer can guess an answer from its length.
- DoH is not served under `/dns-query` on the API's own listener (risk R49 of the Phase 2 plan). It needs an address or port of its own, or the reverse proxy in front of both.

## 8. The query log and dnstap

This page describes the query log of a node's `dns` role: what it writes, where, for how long, how it protects the clients it names, how it is read, and its limits. It is the work of WP5.4 of [phase-2-plan.md](plans/phase-2-plan.md) (section 2.9 and owner decision P2-Q7) and will be folded into `docs/dns-resolver.md` section 8. The role itself, its settings and its commands are in [dns.md](dns.md) section 8.

The decision behind it (P2-Q7): query logs stay on the node that answered and are read through a node command, so that no controller and no copy in the replicated store ever holds them. An installation that wants them elsewhere sends them there with dnstap.

### 8.1 What is logged

One entry per answered query (or one in N with sampling): when the query arrived, the client, the transport (UDP, TCP, DNS over TLS, DNS over HTTPS), the query name and type, the RCODE answered, the view that matched, the block list that blocked it, whether the answer came from the cache, and the microseconds from arrival to answer. A query that the forwarder answers is logged when its answer leaves.

### 8.2 From the query path to the disk

The query path never waits for the log:

1. **The ring.** The answering thread copies the entry into a ring of 8,192 fixed-size slots under a short lock: no allocation, no system call. When the ring is full the entry is dropped and counted.
2. **The writer** is a thread of its own. Every 100 ms it swaps the ring with an empty one (the lock is held for the swap only, so recording goes on while the writer formats and writes) and appends the entries to the current segment, then lets the operating system have them.
3. **A failed write** (a full disk, a directory that was removed or made read-only) drops the batch and counts every entry in it. The segment is cut back to its last whole entry, and the next batch opens a new segment, so a disk that comes back is used again without a restart. The error is logged at most once a minute, with the number of failures since the last line, never once per query.
4. **The counters**: `dropped` (a full ring or a failed write), `written` and `write_errors`, since the role started. They are in the node's status (`GET /api/v1/nodes/{id}/dns`, `query_log`), in the detail of the node command `dns.stats`, and in the metric `tenko_dns_log_dropped_total` ([observability.md](observability.md) section 8.4).

The answers never depend on the log: under a full disk, a slow disk or a burst that overflows the ring, the node answers as before and the drop counter rises (`crates/tenko-dns/src/querylog/tests.rs` turns the directory into a file under a running writer; `tests/querylog_drain.rs` records from eight threads at once and checks that every entry is written or counted).

### 8.3 Files, rotation and retention

The segments are files in `log.path` (default `<data_dir>/dns/querylog`), named `queries-<microseconds>.<format>` after the arrival of their first entry:

- **Rotation.** A segment holds at most a sixteenth of `log.size_mb` (between 1 and 8 MiB) and one UTC day; the first entry of a new day opens a new segment.
- **Retention.** At start, after each new segment and once a minute, segments not written for more than `log.days` days are removed, then the oldest while the directory holds more than `log.size_mb`; the segment being written stays.
- **Recovery.** At start, an unfinished tail of the newest segment (the process stopped in the middle of a write) is cut off: a JSON-lines segment ends after its last newline, a dnstap segment after its last whole frame and gets its STOP frame. A segment with nothing whole left is removed. Nothing about it stops the role.

### 8.4 Formats

#### JSON lines (`format = "jsonl"`, the default)

One object per line:

```json
{"at":"2026-10-17T12:00:00.123456Z","client":"p:3f2a9c0d81b7e645","transport":"udp","qname":"www.example.test","type":"A","rcode":0,"cached":false,"duration_micros":38}
```

`client` is absent when the log keeps no client; `view` and `blocked` appear when they are set; `resolution` says how the answer was found and `subqueries` how many queries the recursive resolver sent for it (section 10.13).

#### dnstap (`format = "dnstap"`)

Frame Streams files (`.dnstap`) that dnstap tools read (`dnstap -r`, `kdig` with its dnstap module, `fstrm_dump`):

```text
START control frame   00000000 | length | 00000002 | 00000001 | 22 | "protobuf:dnstap.Dnstap"
data frame            length (4 octets, big endian, never 0) | one Dnstap protobuf message
...
STOP control frame    00000000 | 00000004 | 00000003        (when the segment is closed)
```

Each query is two data frames: a `Message` of type `CLIENT_QUERY` with the query time and the query message, and one of type `CLIENT_RESPONSE` with the query and response times and the response message. Both carry `socket_family` (INET or INET6), `socket_protocol` (UDP, TCP, DOT, DOH) and `query_address`. The `Dnstap` envelope has `type = MESSAGE`, `identity` (`node-<id>`), `version` (the Tenko version) and `extra`, which says how the client was written: `tenko;client=pseudonym`, `tenko;client=address` or `tenko;client=hidden`, with `;cached` for an answer from the cache.

The ring keeps fixed-size slots, not the messages, so the messages are rebuilt from the logged fields: the header (ID 0, QR and the RCODE, an OPT record for an extended RCODE) and the question. The answer sections are not in the log. The protobuf fields are encoded by hand, without a protobuf compiler; `crates/tenko-dns/tests/dnstap.rs` reads the files back with a Frame Streams reader of its own, a decoder that `prost` derives from the field layout of `dnstap.proto`, and `hickory-proto` for the DNS messages.

Rotation, retention, sampling and the client setting apply as for JSON lines, and the reader of section 8.6 reads both formats.

### 8.5 The clients: pseudonyms, addresses or nothing

What the log keeps of the client (TGL-15):

| Setting | Written | Who can read an address |
|---|---|---|
| `pseudonymise = true` (the default in every profile) | `p:` and the first 8 octets of HMAC-SHA-256 of the address, in hexadecimal; in dnstap an address of the same family made of the first 4 or 16 octets | Nobody through the API |
| `pseudonymise = false` | The address | A principal that may update the node; others see no client |
| `client = "hidden"` | No client field at all; no key is made | Nobody |

**The keys.** Each UTC day has its own random 256-bit key, made by the writer when the first entry of the day arrives. The keys are kept in the file `pseudonym-keys` of the log directory (owner-only on Unix), one line per day, and removed with the last segment of their day.

What this gives:

- A client has the same pseudonym for a whole day, also across a restart of the node, so the queries of one device can be followed within the day.
- The next day it has another, and two days' pseudonyms cannot be linked by anyone who reads only the log.
- The files can be read, copied or exported (dnstap) without exposing addresses: a pseudonym cannot be turned back into an address without the key of its day.
- The node itself can tell which pseudonym an address had on a day still in the log: that is how the reader's client filter finds an address in pseudonymised files.

What it does not protect against:

- Whoever holds `pseudonym-keys` can reverse a pseudonym by trying every address (IPv4 has 2^32): the key file is as sensitive as the addresses. It never leaves the node, the API never returns it, and it is removed with the data it protects. Protect the log directory as you would the addresses.
- Names reveal what a client asked: pseudonymisation hides who, not what. Sampling and short retention reduce how much is kept.
- Within a day, the pattern of a pseudonym's queries may identify a device to someone who knows its habits.

### 8.6 Reading the log

`GET /api/v1/nodes/{id}/dns/log` (scope `dns.read` and read on the node) issues the node command `dns.log.read`, which the role executes on the node that holds the files; in Phase 2 that is the controller's own process, in Phase 5 the same command reaches a remote node. Parameters:

| Parameter | Meaning |
|---|---|
| `cursor` | The `next_cursor` of the previous page; absent for the newest line. A cursor is `<segment>:<offset>` and reads the entries before that offset, then the older segments |
| `limit` | Lines per page, 1 to 1,000 (default 100) |
| `qname` | The name and the names under it, labels compared without case: `example.test` finds `www.example.test`, not `badexample.test` |
| `client` | A pseudonym, or an address. An address also finds the entries where it was written as a pseudonym, through the key of each entry's day; it needs the right to update the node (403 otherwise) |
| `rcode` | The RCODE answered, 0 to 4,095 |
| `from`, `until` | The arrival time window (RFC 3339, both ends included) |

Lines come newest first. One read looks at 64 MiB of segments at most; a narrow filter may therefore answer a page with fewer lines than `limit` and a cursor, and the next read goes on from there. A malformed cursor or filter answers 400 `sys.invalid_value` with the field; a node whose log is off answers 409 `dns.node.not_dns`.

**Audit.** Every page read is recorded as a row of `cluster.node_commands` and audited as `dns.log.read` in the same write, with the principal, the node, the cursor range (`from_cursor`, `to_cursor`), the number of lines and every filter (`filter.qname`, `filter.client`, `filter.rcode`, `filter.from`, `filter.until`). The audit trail therefore says who read whose queries and when.

**Addresses** leave the node only for a principal that may update the node (an administrator): for any other reader the lines of a log that keeps addresses come without a client, and a filter by address is refused. Pseudonyms are shown to every reader of the log.

The web UI shows the log of a node on the DNS page **Query log** (`/dns/log`): the last queries with time, client, transport, name, type, RCODE, latency and the cache and block flags, the filters of the route, paging by cursor, the log's settings and counters, and for administrators the kill switch.

### 8.7 Settings and profiles

The `[dns.log]` section of `tenko.toml` ([deploy/tenko.example.toml](../deploy/tenko.example.toml)); environment variables override it as for every section (`TENKO_DNS__LOG__ENABLED=true`).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | the profile's | Log queries |
| `path` | `<data_dir>/dns/querylog` | The directory of the segments and the key file |
| `format` | `jsonl` | `jsonl` or `dnstap` |
| `days` | the profile's | Days a segment is kept, 1 to 365 |
| `size_mb` | 256 | MiB the directory may hold, 1 to 102,400 |
| `sample` | 1 | Log one query in N, 1 to 1,000,000 |
| `pseudonymise` | `true` | Write pseudonyms instead of addresses |
| `client` | `logged` | `hidden` writes no client at all |

`enabled` and `days` follow the security profile when they are not set (TGL-15). The profile is the stored one after first-run setup, else `[profile] name`:

| Profile | Log | Days | Clients |
|---|---|---|---|
| Home | Off (opt-in) | 7 | Pseudonymised |
| Standard | On | 30 | Pseudonymised |
| Hardened | On | 30 | Pseudonymised |
| Lab | On | 7 | Pseudonymised |

Home is off because TGL-15 makes logging opt-in for the home user. Pseudonymisation is on in every profile, Lab included, although TGL-15 lists Lab as not pseudonymised: a lab that wants addresses sets `pseudonymise = false`. The export of the log with the audit stream that TGL-15 names for Hardened is not built; dnstap files are the path to an external collector. The settings are read at start; a change needs a restart of the node.

### 8.8 The kill switch

Two ways to stop logging:

- **At run time**: `POST /api/v1/nodes/{id}/dns/log/stop` (scope `dns.write` and update on the node), the node command `dns.log.stop`, and `.../start` (`dns.log.start`) to log again; the Stop logging and Start logging buttons of the log page do the same. A stopped log takes nothing from the query path (nothing is dropped, nothing is counted). The state is kept as the marker file `stopped` in the log directory, so the log stays stopped across a restart until it is started again. Both commands are recorded and audited (`dns.log.stop`, `dns.log.start`).
- **In the settings**: `enabled = false` in `[dns.log]` and a restart. The writer does not start, `GET /api/v1/nodes/{id}/dns` has no `query_log`, and the log page says the log is off.

Stopping keeps the files already written until their retention removes them; to remove them at once, delete the segments in the log directory.

### 8.9 Limits

- Only the header and the question of each message are in the dnstap output (section 8.4); the answer records, the query ID and the client port are not kept.
- Forwarded queries are `CLIENT_*` messages; `RESOLVER_*` and `FORWARDER_*` messages towards the upstreams are not written.
- The dnstap identity is `node-<id>`, not the host name.
- A read scans segments from the newest; a filter that matches nothing looks at 64 MiB per page and needs many pages to cover a large directory.
- The pseudonym keys are in the log directory; a backup of that directory carries them (section 8.5).
- The settings need a restart; only the kill switch acts at run time.
- `tenko dns log` in the command-line client is not built; read the log through the API or the UI.

## 9. The home cut-over

The procedure of exit criterion E14 (owner action P2-Q14): a home network sends all of its queries through one Tenko node, which answers the home zones itself, forwards the Active Directory zones to the domain controllers, sends everything else to a DoT upstream and blocks the names of a block list (DNS-02, DNS-15, DNS-21, DNS-23, TGL-14, TGL-22). Nothing in the network changes until the DHCP server hands out the node's address; the rollback is the same setting set back, with the old resolver still running.

Every name and address below is a placeholder. Put in your own:

| Placeholder | Stands for |
|---|---|
| `192.0.2.53`, `2001:db8:1::53` | The node's fixed addresses |
| `192.0.2.1` | The resolver the clients use today (the router, Pi-hole or another server); it keeps running |
| `192.0.2.10`, `192.0.2.11` | The domain controllers |
| `home.example.test` | A zone the node serves (imported, or created with its records) |
| `ad.example.test` | The AD zone, which the domain controllers keep serving |
| `198.51.100.53`, `198.51.100.54`, `dns.example.net` | The chosen DoT upstream: its addresses and the name in its certificate |
| `192.0.2.0/24`, `2001:db8:1::/64` | The home networks |
| `blocked.example.net` | A name on the block list |

### 9.1 Before the day

Each row is done and checked before the DHCP change, in this order.

| What | How | Checked by |
|---|---|---|
| A node with the `dns` role on fixed addresses | `roles = "controller,dns"` and `[dns] listen = ["192.0.2.53:53", "[2001:db8:1::53]:53"]` in `tenko.toml` (or `TENKO_ROLES`, `TENKO_DNS__LISTEN`); the addresses static or reserved on the DHCP server, port 53 free on them and open in the host's firewall to the home networks ([deploy/README.md](../deploy/README.md), "DNS: the dns role and port 53") | `tenko serve` prints `dns role answering on 192.0.2.53:53 ...`; `GET /api/v1/nodes/{id}/dns` has `"serving": true` |
| The home zones | Imported from the zone files of the server that holds them today ([dns.md](dns.md) section 4: the zone page's import, or `POST /api/v1/dns/zones/{id}/records/import` with `dry_run=true` first); the reverse zones of the home prefixes come from IPAM ([dns.md](dns.md) section 7) | `dig @192.0.2.53 nas.home.example.test` answers with the `aa` flag |
| The AD zone to the domain controllers | A forwarding rule per AD zone, plain DNS: `tenko dns forwarder create ad.example.test --upstream 192.0.2.10 --upstream 192.0.2.11`, and the same for each reverse zone the domain controllers hold and the node does not serve. `_msdcs.ad.example.test` and every other name under the AD zone follow its rule | Section 9.2, the AD rows |
| Everything else to the DoT upstream | The root rule: `tenko dns forwarder create . --transport dot --tls-name dns.example.net --upstream 198.51.100.53 --upstream 198.51.100.54` (section 2.1; no upstream is built in, P2-Q5). A root rule in the store wins over `[dns] forwarders` | Section 9.2, the outside rows; the Upstream queries tile counts exchanges |
| A block list | Added and fetched once (section 5); the list's version is on the node | `dig @192.0.2.53 blocked.example.net` is blocked (section 9.2) |
| Who may recurse | Under the Home profile every prefix IPAM knows may recurse, and loopback (section 2.3): every home network that will get the node's address by DHCP is a prefix in IPAM, the guest and IoT networks too. Otherwise a view with its own access list | A query from each network answers; one from outside is refused (section 9.6, TGL-22) |
| The cache and the log | The cache needs nothing (10,000 entries under Home). The query log is off under Home (section 8.7); turning it on for the first days, with pseudonymised clients, helps to find what breaks | `GET /api/v1/nodes/{id}/dns`: `cache_entries`, `query_log` |
| The DHCP lease time | Optional: a day before, lower the lease time of the scopes to an hour, so that the clients follow the change within half an hour (they renew at half the lease); set it back after the cut-over | A client's lease shows the shorter time |
| The old resolver | Left running and unchanged: it is the rollback | `dig @192.0.2.1 www.example.com` answers |

The node is the only resolver the clients get: while it is down they have no DNS until the rollback. A second node to list beside it comes with the cluster data plane (Phase 5). Listing the old resolver as a second server is no fallback: clients choose between the servers on their own, and the blocked names would answer through it.

### 9.2 The check from one client

From a client on a home network, before anything changes for the others, ask the node directly: `dig` on Linux and macOS, `Resolve-DnsName -Server 192.0.2.53 -Name <name> -Type <type>` on Windows, or `nslookup <name> 192.0.2.53` anywhere.

| Ask | Command | Expected |
|---|---|---|
| A name of a home zone | `dig @192.0.2.53 nas.home.example.test A` | NOERROR, flag `aa`, the address of the zone |
| Its reverse | `dig @192.0.2.53 -x 192.0.2.20` | NOERROR, the PTR record |
| An AD name | `dig @192.0.2.53 dc1.ad.example.test A` | NOERROR without `aa`, the address the domain controllers give |
| The AD locator | `dig @192.0.2.53 _ldap._tcp.dc._msdcs.ad.example.test SRV` | NOERROR, one SRV record per domain controller |
| An outside name | `dig @192.0.2.53 www.example.com A`, twice | NOERROR, flag `ra`; the second answer comes from the cache, faster and with a lower TTL |
| A blocked name | `dig @192.0.2.53 blocked.example.net A` | NXDOMAIN (or the answer of the list's action, section 5) with `EDE: 15 (Blocked)` in the OPT pseudo-section |
| Over TCP | `dig +tcp @192.0.2.53 www.example.com A` | As over UDP |

Then point that one client at the node (its DNS server set by hand to `192.0.2.53`) and use it for a day: browsing, the domain logon, the printers, the phones' apps. A domain-joined Windows client registers its name with the server that the AD zone's SOA record names (a domain controller), which the conditional forwarder answers; the registration itself does not go through the node.

### 9.3 The DHCP change

On the existing DHCP server, for each scope of the home networks:

1. Set option 6 (DNS servers) to the node's address alone: `192.0.2.53`. Where the server holds the option per scope, start with one scope and go on with the others after a day. On a Windows DHCP server, for example: `Set-DhcpServerv4OptionValue -ScopeId 192.0.2.0 -DnsServer 192.0.2.53`.
2. IPv6: when the networks announce DNS servers over IPv6 (RDNSS in the router advertisements, or DHCPv6 option 23), set those to `2001:db8:1::53` as well. A client that learns an IPv6 DNS server elsewhere keeps asking it.
3. Wait for the clients: each takes the new server when it renews its lease, at half the lease time, or at once when it reconnects (`ipconfig /renew` on Windows, Wi-Fi off and on on a phone). Clients with a DNS server set by hand (servers, some printers) do not follow: change those where the node should serve them. Leave the domain controllers as they are.
4. Check a few clients: `ipconfig /all` shows `DNS Servers . . . : 192.0.2.53` on Windows, `resolvectl status` on Linux with systemd-resolved, the network details on a phone.

### 9.4 The first hour

The DNS tiles of the start page ([observability.md](observability.md) section 7) show the node live; the query log page shows single queries when the log is on.

| Tile | Healthy | When it is not |
|---|---|---|
| DNS queries | Rises as the clients renew; p50 below a millisecond for cached and home names, p99 near the upstreams' round trip | A p99 far above the Upstream queries tile's round trip: see `problems` in `GET /api/v1/nodes/{id}/dns` |
| Answers | NOERROR the most; NXDOMAIN a few percent (blocked names count here) | SERVFAIL above a few percent: the upstreams or a domain controller do not answer (the Upstream queries tile, `tenko_dns_upstream_queries_total` by `outcome`). REFUSED: clients of a network that is not a prefix in IPAM (section 2.3); add the prefix |
| Cache hit ratio | Rises over the hour as the popular names fill the cache | Stays near zero: the query log shows which names are asked |
| Blocked queries | The lists that block, the busiest three by name | A site or app that stops working: find its names in the query log with the block flag and change the list (section 5) |
| Upstream queries | Exchanges with the DoT upstream, round trip p99 in tens of milliseconds | No exchanges while outside names answer: the root rule is missing and `[dns] forwarders` answers instead |
| DNS queries, the warning line | None | "query log entries dropped": the log's disk is full or slow (section 8.2) |

`GET /api/v1/system/status` warns with `dns.role.not_serving` when the role stops answering: roll back at once.

### 9.5 The rollback

1. On the DHCP server, set option 6 back to `192.0.2.1`, and the IPv6 DNS servers to what they were, scope by scope as they were changed.
2. Renew the leases of the clients that matter now (section 9.3, step 3); the others follow within half a lease time.
3. Leave the node running: nothing else in the network changed, and its dashboard and query log keep what happened for the follow-up.

Roll back when the domain logon fails, when SERVFAIL stays above a few percent for minutes, when the role stops answering, or when the household asks for it.

### 9.6 Verification rows of E14

E14 is met when every row holds on a client that got the node's address by DHCP:

| Requirement | Command | Expected |
|---|---|---|
| E14: the client uses the node | `ipconfig /all` or `resolvectl status` | The DNS server is `192.0.2.53` only |
| DNS-02: the forwarder and the conditional forwarders | `dig dc1.ad.example.test A`; `dig _ldap._tcp.dc._msdcs.ad.example.test SRV` | The domain controllers' answers; `tenko_dns_upstream_queries_total{rule="ad.example.test",outcome="ok"}` grows |
| DNS-15, TGL-14: DoT to the upstream | `dig www.example.com A` for a name not asked before, while `tcpdump -ni any host 198.51.100.53` runs on the node | An answer; the capture shows port 853 only, nothing on port 53; `tenko_dns_upstream_queries_total{transport="dot",outcome="ok"}` grows |
| DNS-21: the block list | `dig blocked.example.net A` | NXDOMAIN (or the list's action) with `EDE: 15 (Blocked)`; the Blocked queries tile names the list |
| DNS-23: the cache | `dig www.example.com A` twice | The second answer's TTL is lower by the seconds between them; the cache hit ratio tile is above zero |
| TGL-22: the recursion access list | From an address outside the home prefixes (a lab host on `198.51.100.0/24` routed to the node): `dig @192.0.2.53 www.example.com A` | REFUSED with `EDE: 18 (Prohibited)`; from the home networks, an answer |
| The home zones | `dig nas.home.example.test A`; `dig -x 192.0.2.20` | Answers with `aa` from the node |

Record the date, the lease time used and the findings in the Phase 2 status (`docs/plans/phase-2-status.md`).

### 9.7 The recursion variant (Slice 10)

A node can resolve outside names itself instead of sending them to a DoT upstream (section 10). The cut-over of this section stays as it is, except for the one row of section 9.1 that names the root rule: with recursion there is no root rule, the clients' queries are resolved from the root servers down, and the AD zones still go to the domain controllers through their own rules, because a rule with a longer suffix wins. The home zones, the block list, the recursion access list, the DHCP change and the rollback do not change. The node does not check DNSSEC signatures yet (section 10.16) and never sets AD.

| Subject | With the DoT upstream (9.1 to 9.6) | With recursion |
|---|---|---|
| The rule for everything else | A root rule over DoT; it wins over `[dns] forwarders` | None. A node with the `dns` role recurses for names no rule or stub zone covers, in every profile (section 10.1). A root rule in the store still wins over recursion |
| What the node must reach | The upstream's addresses on port 853 | Every authority server of the Internet on UDP and TCP port 53, over IPv4 and, where the node has a route, IPv6. A firewall that lets only the old resolver out has to open port 53 for the node |
| Queries to the Internet | One exchange per name, encrypted | Several exchanges per name from a cold cache (three or more, section 10.15), in plain text: nothing protects the path to an authority (section 10.16). The answer cache and the infrastructure cache make the later ones cheaper |
| The E14 row for DNS-15 and TGL-14 (section 9.6) | DoT to the upstream | Does not apply. A household that wants one operator it trusts to see its queries keeps the DoT root rule |

The resolver is on by default, so a node that has `[dns] forwarders` in `tenko.toml` and no root rule in the store recurses as soon as it runs a version with the resolver: it no longer sends everything to those forwarders. To keep forwarding, add a root rule (below) or set `[dns.recursion] enabled = false` and restart the node.

**Checking that the resolver works.** Each check is made on the node, from a client of a home network:

| Check | How | Healthy |
|---|---|---|
| The resolver runs and has primed | `GET /api/v1/nodes/{id}/dns/recursion`, or the Recursion page of the DNS area (`/dns/recursion`) | `enabled` is true, `last_priming` has the outcome `ok` and a duration of tens of milliseconds, `root_servers` lists the root servers with round-trip times, `problems` is empty |
| An outside name | `dig @192.0.2.53 www.example.com A`, twice | NOERROR with the flag `ra`; the first answer takes the walk from the root (`counters.subqueries` grows by three or more), the second comes from the cache with a lower TTL. With the query log on (section 8), the lines say `resolution: recurse` with `subqueries`, then `resolution: cache` |
| The root servers answer | `problems` of the status | No `priming_failed`. When it is there, no root server of the hints answered the last priming: check that the node may send UDP and TCP to port 53 outward, and that `hints_source` is the file or the shipped hints you expect. `POST /api/v1/nodes/{id}/dns/recursion/prime` tries again at once, and the node tries again by itself after 1 second, then 2, up to 5 minutes |
| A name that fails | `dig @192.0.2.53 broken.example.com A` | SERVFAIL with `EDE: 22 (No Reachable Authority)` when the authorities of the name do not answer or a bound of the work budget was hit, `EDE: 23 (Network Error)` when the node could not send to any of them. Asking again within 5 seconds sends no query to an authority (section 10.3); `counters.failure_cache_hits` counts it |
| What the node knows about a zone | `GET /api/v1/nodes/{id}/dns/infra?suffix=example.com` | The zone cut with its name servers, their addresses and where each came from, their smoothed round-trip times and flags: `lame` for a server that is not an authority of the zone, `edns` false for one that does not take EDNS, `tcp_only` |
| A stale picture of an authority | `POST /api/v1/nodes/{id}/dns/infra/flush`, with `?suffix=example.com` for one zone and what is below it | The zone cuts and name servers at or below the suffix are dropped. Without a suffix everything goes, the figures and capabilities of every server too, the root's servers come back from the hints and the root is primed again. The answer cache and the failure cache keep what they hold; `POST /api/v1/nodes/{id}/dns/cache/flush` (section 3.5) empties the first |

**The fallback in one command.** If recursion misbehaves for the household, a root forwarding rule over DoT takes the names back at once, with no restart, from the next revision the node applies:

```sh
tenko dns forwarder create . --transport dot --tls-name dns.example.net \
  --upstream 198.51.100.53 --upstream 198.51.100.54
```

The rules for the AD zones and for any other suffix stay as they are. Answers already in the cache keep their TTLs. To return to recursion, delete the rule with `tenko dns forwarder delete .`. To switch the resolver off for the whole node, set `[dns.recursion] enabled = false` and restart it; `[dns] forwarders` then serves as it did before Slice 10.

## 10. Recursion

This section describes the recursive resolver of a node with the `dns` role: Tenko's own iterative engine, which answers a name outside the node's zones by asking the root servers, then the servers of each delegation down to the authority of the name, with no upstream resolver in between (DNS-03, DNS-08, DNS-21, WP10.1 of the recursion plan, [dns-recursion-plan.md](plans/dns-recursion-plan.md) sections 2.1, 2.2, 2.7 and 2.10 to 2.12; the decision is [ADR 0021](adr/0021-recursive-resolution-and-validation.md)). The code is `crates/tenko-dns/src/recurse.rs` and its modules (`message`, `net`, `hints`, `local`, `join`) and `crates/tenko-dns/src/infra.rs` (the infrastructure cache and the figures of the servers); the contracts they implement are `crates/tenko-dns/src/recursion`. The engine runs on the forwarder's task pool and allocates freely; steps 1 to 7 of section 1 stay allocation-free (ADR 0009). The conformance rows are in [CONFORMANCE.md](CONFORMANCE.md).

What this section describes is resolution. Validation of DNSSEC signatures is [dnssec.md](dnssec.md) section 12 (WP10.2); QNAME minimisation, the denial cache and the bounded failure cache are section 11 (WP10.3); section 10.16 lists what is not built.

### 10.1 What the resolver does, and in which order

The lookup order of section 1 has one more route and one more default. A query passes steps 1 to 5 as before (the header, the rate limiter, the view, the zones, the policy, RD, and the view's recursion access list of section 2.3, which is checked before any route). Then:

| Step | What |
|---|---|
| 6. A route | The longest suffix among the forwarding rules and the stub zones decides, as in section 2. A rule has a **mode**: `forward` (its upstreams, as in section 2.1) or `recurse` (no upstreams: the names under its suffix are resolved by the engine, so a root rule that forwards can have a `recurse` rule for one suffix, and the other way round). When no rule and no stub zone covers the name, the **view's resolution** decides: `recurse`, `forward` (the default forwarder of `[dns] forwarders`) or `refuse`. A view without a resolution recurses, in every profile (REC-Q2). A node whose resolver is off (`[dns.recursion] enabled = false`) forwards instead |
| 7. The cache | The answer cache, as in section 3 |
| 8. The runtime | The forwarder for a `forward` route, the engine for a `recurse` route. Both fill the same cache and answer through the same reply path |

A `forward` resolution with no default forwarder is answered REFUSED with the extended error "Not Authoritative" (20); `refuse` is REFUSED with "Prohibited" (18). `[dns] forwarders` is therefore used only where a view says `forward`, or on a node whose resolver is off; it is never a silent default beside the resolver.

A rule's `mode` and a view's `resolution` are rows of the store and the engine follows them; they are set through the API, the command line and the forwarders page (section 2.1). A view without a `resolution` follows the profile's default, which recurses, so a node recurses for every name its rules and stub zones do not cover unless a view or a rule says otherwise.

The engine's answers go into the cache that forwarded answers go into, and are served from it as any other: positive answers for the smallest TTL of their records, NXDOMAIN and NODATA with the SOA for the negative TTL (section 3.1). A query with CD set is resolved but its answer is not cached, so that data one client asked for with CD never reaches the entry other clients share. A resolution that fails with SERVFAIL answers a stale entry when the cache holds one (section 3.3). The prefetch of section 3.4 asks the engine for an entry the engine made. The answers carry the authority's records as they came, RRSIG records included for a client that asked with DO; AA and AD are clear, and RA is set.

### 10.2 The algorithm

**Priming (RFC 8109).** At start, when the root's NS set is nearly expired, after the hints file changed, after a flush of the infrastructure cache and on request (section 10.12), the resolver asks a root server for `./NS`, without RD, with EDNS and DO. It tries at most six addresses of the families in force one after another, the fastest it has measured first and the others in a random order. The NS set of the answer and the addresses in its additional section become the root's servers for the NS records' TTL (at most seven days). The next priming is due a tenth of that TTL before it ends, at most an hour before. The hints are the file shipped in the binary (`crates/tenko-dns/anchors/named.root`, with its date) or the file `[dns.recursion] hints` names, in the zone file format of `named.root`; they are never downloaded, and a hints file whose modification time changed is read again (checked once a minute) and primed from at once. While no root server answers, the hints stay the root's servers, so resolution goes on if any of them is reachable; priming is tried again after 1 second, then 2, doubling up to 5 minutes, and `priming_failed` is in the `problems` of the resolver's status and of the node's status until a priming succeeds. A node whose hints name no reachable server answers every name SERVFAIL with the extended error 22 "No Reachable Authority". The first resolutions after a start may run before the priming has answered, from the hints.

**The walk.** For a name and type the resolver takes the closest zone cut it holds in the infrastructure cache (the longest suffix of the name with an NS set that has not expired, the root at worst; for a DS query a cut above the name itself), chooses a server of the cut (section 10.4) and asks it for the name and type, RD clear. It reads the answer for the zone it asked, as RFC 2181 section 5.4 ranks it and RFC 9471 bounds it:

| The answer | What the resolver does |
|---|---|
| AA set, with the records of the type asked at the name (or at the end of a CNAME chain inside the zone) in the answer section | The answer. The records of the chain and the RRset with the RRSIG records that cover it are kept |
| A CNAME at the name, or a DNAME above it, and nothing for the target inside the zone | Restarts the walk for the target (below) |
| NXDOMAIN, or NOERROR without data, with AA or with an SOA of the zone in the authority section | A negative answer. The SOA, NSEC and NSEC3 records of the zone and their signatures are kept for the answer |
| NOERROR without AA and NS records in the authority section, owned by one zone strictly below the zone asked and at or above the name (for DS, strictly above it) | A referral: the walk moves down one cut |
| Anything else (below) | The server is lame |

A server is **lame** for the zone it was asked when it answers with an RCODE other than NOERROR and NXDOMAIN (REFUSED, SERVFAIL, BADVERS and the others), echoes another question, gives an answer without AA, refers upward or sideways or to more than one zone, answers a CNAME or DNAME it cannot read, or answers a negative answer with an SOA from a zone above the one asked, which is what a server of the parent does for a delegation it does not serve. A lame server is marked lame for that zone in its entry of the infrastructure cache for the infrastructure TTL (section 10.10) and skipped while another server of the cut exists. When every server of a cut is lame, unreachable or out of attempts, the resolution ends: SERVFAIL, extended error 22.

**Ranking and the bailiwick rule.** Only what the zone's own server may say about the zone is used: an answer section of an authoritative answer; records for a name outside the zone that was asked are not used (a CNAME to such a name is followed from the start instead, below). A referral's NS set is cached as the delegation of the child zone, with its smallest TTL (at most one day). Its additional section is read by the bailiwick rule of RFC 9471, for each name server the referral names:

- **In-domain glue**, for a name server at or below the delegated zone, is cached as the name server's addresses with the origin `glue`.
- **Sibling glue**, for a name server inside the zone that was asked but outside the delegated zone (for example a server in the sibling zone of the same parent), is used for this step and cached with the origin `sibling_glue`.
- **Every other address** in the additional section is ignored: never cached, never asked. Glue for a name that is not in the referral's NS set is ignored as well.

A name server's addresses carry their origin, ranked `hints` below `sibling_glue` below `glue` below `authoritative` (an address looked up from the name server's own authority). An address of a lower rank never replaces an address of a higher rank that has not expired (RFC 2181 section 5.4.1). The origin shows in the listing of section 10.12. The confirmation of sibling glue by an answer from the glue's own authority is not built: a `sibling_glue` address is used as any other and stays marked until a lookup of the name replaces it.

**Name-server addresses.** A cut whose name servers have no address of a family in force gets them by sub-queries through the same engine: A, then AAAA when A gave nothing (A only under `v4`, AAAA only under `v6`). The fetch policy of Unbound bounds them: three such lookups at the depth of the client's question, then two one level down, then one, then none, so that with the defaults they nest three levels deep; `budget_depth` cuts them shorter when it is set lower. A name server whose lookup is in progress is not looked up again inside itself: a delegation whose servers can only be found through each other (`loop.example.test` and `loop2.example.test` naming each other's servers without glue) is a loop, and the resolution ends with SERVFAIL and the extended error 22. The queries of a lookup are counted in the work budget.

**CNAME and DNAME.** A CNAME at the name restarts the walk for its target, at most 8 links per name (`budget_restarts`), counting every CNAME record in the chain; a DNAME above the name adds the CNAME that RFC 6672 section 3.4 says the server synthesises, with the DNAME's TTL, and restarts for the substituted name (a substitution longer than 255 octets makes the server lame). A target already seen, or a ninth link, ends the resolution: SERVFAIL, extended error 22, the chain so far in the answer. The answer to the client carries the whole chain, each CNAME with its own TTL.

### 10.3 The work budget and the failure cache

One client query may cause at most the work of this table (REC-Q12). The bounds are `[dns.recursion]` settings (section 10.14) except the attempts and the fetch policy. A bound that is hit ends the resolution: SERVFAIL with the extended error 22 "No Reachable Authority", the failure remembered, and the counter that names the bound raised.

| Bound | Default | What moves it | Counter of the status |
|---|---|---|---|
| Queries sent to authorities | 32 | Every query to an authority server: the sub-queries for name-server addresses, and the queries the fallback ladder repeats (the retry without EDNS, the retry over TCP after a truncation, the retry in lower case after a 0x20 mismatch, and every attempt after a timeout). The retry after BADCOOKIE is not counted | `budget_queries` |
| CNAME and DNAME links | 8 | Each CNAME record in the chain of one name | `budget_restarts` |
| Depth of name-server lookups | 6 | A name-server lookup that needs a name-server lookup (the fetch policy stops them at three levels with the defaults) | `budget_depth` |
| Attempts per server and question | 3 | Each attempt at one server address in one step of the walk. A fourth is not made: the server is skipped. A 0x20 mismatch retried in lower case does not use an attempt | none |
| Wall clock | 10,000 ms | The time from the hand-off to the answer | `budget_time` |

The extended error 23 "Network Error" is for a step in which every attempt failed because the query could not be sent at all; a server that is only silent or lame is error 22.

**The failure cache (RFC 9520).** A resolution that ends in SERVFAIL, whatever the cause, is remembered per view, name, type and class: for 5 seconds, then twice as long each time the same question fails again within the hold or as long again after it, up to `failure_cache_max_secs` (300). While a failure is remembered the question is answered SERVFAIL with the same extended error and no query is sent to an authority; it is counted in `failure_cache_hits` and `tenko_dns_failure_cache_hits_total` and not as a resolution. Since WP10.3 the cache is bounded, looked up on the worker as well and flushed with the answer cache (section 11.4).

### 10.4 Server selection and timeouts

A cut's servers are the addresses of its name servers that are of a family in force (section 10.7), not lame for the zone, not marked unreachable and not out of attempts for this question. The resolver asks:

1. The address asked least often for this question, so that attempts spread over the servers before one is asked a second time.
2. Among those, the addresses not in back-off before the ones in back-off, and among those the one with the smallest smoothed round-trip time; an address never measured counts as the fastest, so it is measured first. One choice in 16 goes to a random one of the addresses not in back-off, so that the times of the others stay current.

The figures per address are those of the upstream pool (section 4.7), kept per address because a delegation's servers are shared by many zones: the smoothed round-trip time (SRTT) is an exponentially weighted mean with weight 1/8 per answer, doubled by a failure; the p50 and p99 come from the answers of the last minute, at most the last 32; three failures in a row put the address in back-off for 1 second, doubling with each further failure up to a minute, and an answer ends it.

The timeout of an attempt is four times the address's SRTT, at least 300 ms and at most `timeout_ms` (2,000); for an address never measured it is half of `timeout_ms`, at least 300 ms. A silent server therefore costs a few seconds, not the whole budget: three attempts of 1, 2 and 2 seconds with the defaults. An address in back-off is asked only when no other address of the cut is left.

### 10.5 The defences (DNS-08)

Every query to an authority carries these, and the answer is used only if it matches them:

- **0x20.** The letters of the question name get a random case, and the answer must carry the question in exactly that case. A mismatch is retried at once in lower case and counts as a strike for the server; after two strikes the address is asked in lower case for the infrastructure TTL, and the case is no longer checked for it. The lab has a server that breaks 0x20 on purpose (section 10.15).
- **A fresh source port.** Each exchange binds a socket of its own to a random port and drops it after the answer (`[dns.recursion] fresh_port_per_query`, on). With the key off, authorities are asked from the shared sockets of the upstream pool, each used for up to 64 exchanges. What the bind costs is measured by M36 (WP10.5).
- **Cookies (RFC 7873, RFC 9018).** The client cookie is 8 octets, the SipHash-2-4 of the server's address under a random 16-octet secret the engine makes at start. A server cookie that comes back is kept in the server's entry of the infrastructure cache and sent from then on. An answer whose cookie option carries another client cookie, a cookie to a query that sent none, a server cookie of a bad length or broken options is not ours: over UDP it is ignored like any unwanted answer, over TCP it is a malformed answer. BADCOOKIE is asked again once, with the server cookie the answer carried; a second BADCOOKIE, or one without a server cookie, is a failure. A server that never returns a cookie costs nothing.
- **Unwanted answers.** A datagram on an exchange's socket that matches no outstanding query (another source address or port, another id, another question, a foreign cookie) is dropped, the wait goes on, and it is counted for the server asked. A server that draws more than 1,000 in an hour is asked over TCP for the rest of the hour; more than 100,000 across the node in an hour flushes the answer cache, as Unbound's `unwanted-reply-threshold` does, and the flush is logged and audited as `dns.recursion.unwanted_flush` with the number of entries. The count is `unwanted` in the status, the flushes `unwanted_flushes`.
- **Identical queries in flight** are joined (section 10.9).

### 10.6 The EDNS and transport ladder

Every query carries an OPT record: version 0, 1,232 octets, DO (a validator always asks for signatures, RFC 3225) and the cookie option. There is no step to 4,096 or to 512: 1,232 is the one size. The ladder is the one of RFC 8906 and the DNS flag days of 2019 and 2020:

| Event | What the resolver does |
|---|---|
| FORMERR or NOTIMP, without an OPT record, to a query with EDNS | The same question once more without EDNS (and so without DO and the cookie). The server is marked as taking no EDNS in its entry, and later queries to it go without EDNS from the start |
| A timeout | The same query again, with EDNS. A timeout is never a reason to drop EDNS |
| A truncated UDP answer (TC) | The same question over TCP: one connection per exchange, the two-octet length prefix of RFC 7766, within the attempt's deadline, with the same checks of id, question, case and cookie |
| Three truncated answers in a row from one server | The server is marked TCP-only: asked over TCP from the start |
| An answer without an OPT record to a query with EDNS, for another reason | Treated as a server without EDNS |

TCP connections are not reused and queries are not pipelined: each exchange over TCP opens a connection and closes it. The retries of the ladder are queries in the work budget (section 10.3).

### 10.7 IPv4 and IPv6

`[dns.recursion] outbound` (REC-Q9) chooses the families:

| Value | Meaning |
|---|---|
| `auto` (default) | Both. A server is asked on its fastest address. An IPv6 address to which the query cannot be sent (no route, or the network refuses it at once) is marked unreachable for 6 hours and skipped; a successful answer clears the mark. The node does not read its own addresses: a node without IPv6 pays one failed attempt per IPv6 server address per 6 hours |
| `both` | Both, and an address is never skipped |
| `v4` (`ipv4`) | IPv4 addresses only; name-server lookups ask A only |
| `v6` (`ipv6`) | IPv6 addresses only; name-server lookups ask AAAA only. Such a node resolves only zones with an IPv6 name server |

### 10.8 Special-use and locally served names

A name under one of 41 zones never reaches an authority: seven names of the special-use registry (RFC 6761, RFC 6762's `local`, RFC 7686's `onion`, RFC 8375's `home.arpa`) and 34 reverse zones of RFC 6303. The first rule is that a zone or a forwarding rule of the node answers such a name when it covers it (step 2 and step 6 come first); the engine answers the rest, on the runtime, and counts them as `local`:

| Zones | Answer |
|---|---|
| `localhost`, `invalid`, `test`, `example`, `onion`, `local`, `home.arpa` | NXDOMAIN for every name at or below them, with the zone's SOA in the authority section |
| `10.in-addr.arpa`, `16.172.in-addr.arpa` to `31.172.in-addr.arpa`, `168.192.in-addr.arpa`, `0.in-addr.arpa`, `127.in-addr.arpa`, `254.169.in-addr.arpa`, `2.0.192.in-addr.arpa`, `100.51.198.in-addr.arpa`, `113.0.203.in-addr.arpa`, `255.255.255.255.in-addr.arpa` | Empty zones (RFC 6303): the apex answers its SOA, and its NS record (the zone itself) for NS; any other type at the apex is NOERROR without data with the SOA; every name below the apex is NXDOMAIN with the SOA |
| In `ip6.arpa`: the zones of `::` and `::1`, `c.f` and `d.f` (fc00::/7), `8.e.f`, `9.e.f`, `a.e.f` and `b.e.f` (fe80::/10), and `8.b.d.0.1.0.0.2` (2001:db8::/32) | The same |

The SOA is the one RFC 6303 section 3 writes: the zone as the primary name server, `nobody.invalid.` as the mailbox, the serial 1, and 10,800 seconds as the TTL and the minimum, so that the answer is cached as a negative answer. `[dns.recursion] local_zones_except` lifts zones: each name lifts the listed zones at or below it, so `test` lifts the zone `test`, `10.in-addr.arpa` lifts that zone, and `arpa` lifts every reverse zone. The lab lifts `test`, which it uses for its own names. A local answer comes from the engine, after the cache and the hand-over, and is cached; it is not answered on the worker yet (section 10.16).

### 10.9 Identical queries in flight

Client queries with the same name, type, class and view that arrive while one of them is being resolved wait for that resolution and share its answer (the join table, in `recurse/join.rs`; `joined` in the status counts them). A burst of one name costs one resolution, and an attacker cannot have many identical queries outstanding at once, which is what the birthday attack on outstanding queries needs. The table lives on the runtime; the worker hands queries over as before. If the resolution that leads a group is dropped, the others resolve on their own.

### 10.10 The infrastructure cache

The infrastructure cache (`tenko_dns::infra`) holds what the engine learns about the servers it asks. It is read and written on the runtime only, never on the worker, so it may allocate and lock freely, and it holds no client data.

| Per | What it holds |
|---|---|
| Zone cut | The zone, its name servers' names, when the NS set expires (the referral's smallest TTL, at most one day; the root's from the priming), the DS state the validator fills (`unknown`, `secure` with the keys, `insecure` or `bogus`; [dnssec.md](dnssec.md) section 12) and a slot for the minimisation fallback of WP10.3 |
| Name server | Its A and AAAA addresses with their TTLs and origins (section 10.2) |
| Server address | What the resolver learnt: whether it takes EDNS (unknown, yes, no), TCP-only, the server cookie, the zones it is lame for, each until a time, the time of its last failure, and the mark that the address is unreachable. Beside them, the figures of section 10.4 (SRTT, p50 and p99, failures and back-off), the 0x20 strikes, the unwanted answers of the hour and the TCP hour they cause |

The bounds are zone cuts and server addresses: 1,000 and 2,000 under the Home profile, 10,000 and 20,000 under the others; `infra_entries` sets the cuts and the addresses follow at twice that. The name servers' table and the figures of the servers have the bound of the addresses. A map over its bound drops its least recently used sixteenth at once, so an insert at the bound costs one scan per sixteenth of the bound, not one per insert. Expired cuts, addresses and server entries with nothing left to remember are purged once a minute. `infra_ttl_secs` (900) is the time a learnt lameness and a learnt need for lower case hold; the unreachable mark holds 6 hours; what the resolver learnt about a server's EDNS, TCP and cookie is kept with the server's entry until the least-recently-used rule drops it or a flush empties it. The sizes against the bounds are in the status, and in `tenko_dns_infra_entries{kind}`.

### 10.11 The RPZ triggers NSDNAME and NSIP

A forwarding resolver cannot match the triggers `rpz-nsdname` and `rpz-nsip` of an RPZ zone (section 5.2): it sees only what the upstream's answer carries. The recursive resolver knows the delegation it followed. While any RPZ zone of the catalog has an NSDNAME or NSIP trigger, the engine's answers carry the NS records of the zone cut that gave the answer in the authority section and the addresses it holds for those name servers in the additional section, and the policy matches them as it matches a forwarded answer's (section 5.1). The node looks at the catalog every 200 ms. A name whose answer came from a server named by an NSDNAME trigger, or from an address in an NSIP trigger's prefix, is blocked by the zone's action. Only the cut that gave the answer is matched, not the cuts above it, and an entry cached before such a trigger existed carries no delegation: flush the cache (section 3.5) after the first NSDNAME or NSIP trigger is added. The lab round has a row for each trigger (section 10.15 and the lab's README).

### 10.12 The status, the priming and the infrastructure cache

Four routes and three node commands (`dns.recursion.prime`, `dns.infra.list`, `dns.infra.flush`), run on the node that holds the resolver; in this slice that is the controller's own process, as for the cache (section 3.7). A node that does not run the `dns` role answers 409 `dns.node.not_dns`; the three commands, on a node whose resolver is off, answer 409 `dns.recursion.disabled`.

| Route | Scope | What |
|---|---|---|
| `GET /api/v1/nodes/{id}/dns/recursion` | `dns.read` | The resolver's status |
| `POST /api/v1/nodes/{id}/dns/recursion/prime` | `dns.write` | Prime now. 202 with the id of the recorded command; a priming already running is left to finish. Audited as `dns.recursion.prime` |
| `GET /api/v1/nodes/{id}/dns/infra` | `dns.read` | A page of the infrastructure cache. Recorded as a node command and not audited: the cache holds the authority servers of zones and no client data |
| `POST /api/v1/nodes/{id}/dns/infra/flush` | `dns.write` | Drop the infrastructure cache, or with `?suffix=` the zone cuts and name servers at or below it. 200 with `entries`, the number dropped. Audited as `dns.infra.flush` with the suffix |

**The status** answers 200 also when the resolver is off (`enabled: false`, empty and zero fields). Its fields:

| Field | Meaning |
|---|---|
| `enabled`, `hints_source`, `hints_date` | Whether it runs; `shipped` or the path of the hints file; the date of the shipped hints or the file's modification date |
| `last_priming` | `at`, `outcome` (`ok` or `failed`) and `duration_ms`; absent before the first priming |
| `root_expires_secs` | Seconds until the root's NS set expires |
| `root_servers` | The root servers in use: `name`, `address` and `srtt_ms` |
| `infra` | `zones` and `servers` against `max_zones` and `max_servers`, and `names` |
| `budget` | The work budget in force: `queries`, `restarts`, `depth`, `attempts`, `wall_ms` |
| `counters` | Since the role started: `answered`, `servfail`, `budget` (the queries, restarts or depth bound), `timeout` (the wall clock bound), `local`, `failure_cache_hits`, `joined`, `subqueries` (queries sent to authorities), `budget_queries`, `budget_restarts`, `budget_depth`, `budget_time`, `primings_ok`, `primings_failed`, `unwanted`, `unwanted_flushes`; and the validation outcomes `secure`, `insecure`, `bogus`, `indeterminate` |
| `trust_anchors` | The keys of the trust anchors with their RFC 5011 state and source |
| `problems` | `priming_failed`, `clock` (the root's DNSKEY signatures fail on time: OPS-09) and `trust_anchor_stale` (a zone without a trusted key left). The node's own status (`GET /api/v1/nodes/{id}/dns`) names `dns.recursion.priming_failed` in its `problems` too |

**The listing** takes `suffix` (the zone cuts at or below it), `limit` (1 to 1,000, default 200) and `cursor` (the `next_cursor` of the previous page), and answers the zone cuts sorted by name. Each cut has `zone`, `ds` (`unknown`, `secure`, `insecure` or `bogus`), `ttl` (seconds left) and its `servers`; each server has `name` and `addresses`; each address has `address`, `origin` (`hints`, `sibling_glue`, `glue` or `authoritative`), `ttl`, `srtt_ms`, `p50_ms`, `p99_ms`, `failures`, `down` (in back-off), `edns` (`true`, `false`, or absent when not learnt yet), `tcp_only`, `lame` (for this cut's zone), `lower_case` (asked in lower case) and `unwanted`. A malformed `suffix`, `cursor` or `limit` answers 400 `sys.invalid_value` with the field.

**The Recursion page** of the DNS area (`/dns/recursion`) shows the status first: the hints source and date, the last priming with a **Prime now** button, the root servers with their SRTT, the infrastructure cache's sizes, the counters, and the validation counters (secure, insecure, bogus, indeterminate) with the anchor keys and their states. Then the trust anchors, one card per zone (the root first): each key with its tag, algorithm, form (a DS digest type or a DNSKEY), RFC 5011 state and since when, its source (shipped in a release, added by an operator, learned by RFC 5011) and when it was last seen, the zone's last and next query, and for those who hold `dns.keys` **Refresh now** (RFC 5011 at once), **Remove** after a confirmation and **Add a trust anchor** (a zone and a DS or DNSKEY record). The root is replaced or removed under the Lab profile only; elsewhere its actions give `dns.trust_anchor.root_protected` as the reason. Last, the negative trust anchors with their expiry (how long from now; one past its expiry shows as expired until the list is read again: the server lists only the living ones, and the leader service deletes the row at its next pass, once a minute), reason and creation time, a form that asks for the zone, a lifetime of at most seven days (`12h`, `2d`) and the reason, and a delete action. Both lists follow the `dns` topic.

**The infrastructure cache browse** is the section **Infrastructure cache** of the DNS settings page (`/settings/dns`), beside the settings of the node; the cache listing of section 3.7 is the Cache tab of the DNS page. It reads nothing until asked, then shows a card per zone cut a page at a time (50), with the zone filter: whether the delegation is signed, how long the cut stays, and per name server and address where the address came from, its SRTT and p99, its failures and its capabilities (EDNS or none, TCP only, lower case only, lame, unreachable). **Flush** empties the cuts at or below the zone typed, or everything (the root is primed again with the next query), after a confirmation. A node whose resolver is off says so.

**The query log page** shows the columns **Validation** and **Extended error** (the RFC 8914 code with its registry name) beside **Resolution** and **Sub-queries**, and narrows the page shown to one validation state. **The start page** shows, while the resolver runs, the tiles **Sub-queries** (queries sent to authorities per second, the validator's included) and **Validation** (secure, insecure and bogus answers per second, indeterminate in the hint) beside the upstream tile, from the `recursion` part of the `metrics` samples (`tenko_dns_authority_queries_total` and `tenko_dns_validation_total`).

**The first-run wizard**'s DNS step asks first how names are resolved: **Resolve names yourself** (the default) or **Forward to a resolver of your choice**, with the privacy sentence of the forwarders page. Only the second asks for the upstreams (one at least), their transport and TLS name, and writes them as the root forwarding rule after setup; the first writes no rule and the generated `[dns]` section has `forwarders = []`.

**The command line:**

```text
tenko dns recursion status <node>
tenko dns recursion prime <node>
tenko dns recursion infra <node> [--suffix example.test]
tenko dns recursion flush-infra <node> [--suffix example.test]
tenko dns trust-anchor list|add <zone> --ds <digest>|--dnskey <record> [--replace-root]|remove <zone>|refresh <zone>
tenko dns nta list|add <zone> --expires <duration> --reason <text>|remove <id>
```

### 10.13 Metrics and the query log

The role registers these families when the resolver is on (names as the metrics endpoint prints them; each counter is a per-shard relaxed atomic, OPS-21):

| Family | Labels | What | Counted since |
|---|---|---|---|
| `tenko_dns_recursion_total` | `outcome`: `answered`, `servfail`, `budget`, `timeout`, `local` | Resolutions the engine ended. An answer from the failure cache is not one | WP10.1 |
| `tenko_dns_recursion_duration_seconds` | | Time from the hand-off to the answer (the forwarder's buckets) | WP10.1 |
| `tenko_dns_recursion_subqueries` | | Queries sent to authorities per resolution that sent any, buckets 1, 2, 3, 4, 6, 8, 12, 16, 24 and 32 | WP10.1 |
| `tenko_dns_authority_queries_total` | `transport`: `udp`, `tcp`; `outcome`: `ok`, `referral`, `lame`, `timeout`, `unreachable`, `malformed`, `tc`, `badcookie` | Exchanges with authority servers. `malformed` includes the 0x20 mismatches and answers that do not parse; `tc` is the UDP leg of an exchange that went on over TCP | WP10.1 |
| `tenko_dns_authority_rtt_seconds` | | Round-trip time of answered exchanges, in one histogram: the figures per server are in the listing of section 10.12, not in a label | WP10.1 |
| `tenko_dns_infra_entries` | `kind`: `zone`, `server` | Entries of the infrastructure cache | WP10.1 |
| `tenko_dns_failure_cache_hits_total` | | Questions answered from the failure cache, by the worker (WP10.3) or the engine | WP10.1 |
| `tenko_dns_priming_total` | `outcome`: `ok`, `failed` | Priming runs | WP10.1 |
| `tenko_dns_validation_total`, `tenko_dns_validation_verifications_total` | `state`, `reason` | Validation outcomes and signature checks | WP10.2 |
| `tenko_dns_denial_total` | `kind`: `nxdomain`, `nodata`, `wildcard`, `nxdomain_cut` | Answers synthesised from the denial cache (section 11.2) | WP10.3 |
| `tenko_dns_trust_anchor_keys` | `zone`, `state` | Trust anchor keys by RFC 5011 state | WP10.2 |

**The query log** (section 8) gains two fields. `resolution` says how the answer was found: `zone` (a zone of the node), `cache`, `denial` (WP10.3), `stale`, `forward` (a rule's upstream, a stub zone or the default forwarder), `recurse`, `local` (a locally served name, section 10.8), `policy` (a block list or an RPZ zone) or `refused`. `subqueries` is the number of queries the engine sent to authorities for the answer, and is left out of a JSON line when it is 0. The dnstap output (section 8.4) carries both in the `extra` field as `;resolution=<how>` and `;subqueries=<n>`. The reader, the API's lines and the Query log page show them. `validation` (the security state) and `ede` (the extended error code) are logged since WP10.2 and go into the dnstap `extra` field as `;validation=<state>` and `;ede=<code>`.

### 10.14 Settings: `[dns.recursion]`

The keys of the section ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)); environment variables follow the usual pattern (`TENKO_DNS__RECURSION__ENABLED=false`). `tenko config check` validates every key against its bounds. The keys are read at start and a change needs a restart, except that a changed hints file is read again by itself (section 10.2). The keys that are not set follow the profile in force.

| Key | Default | Consumed by | Meaning |
|---|---|---|---|
| `enabled` | on in every profile | WP10.1 | Run the resolver. Off: no engine, no recursion metrics, and `[dns] forwarders` serves as it did in Phase 2 |
| `hints` | not set: the shipped hints | WP10.1 | A root hints file in the format of `named.root`. A file that cannot be read stops the start (`config.invalid`) |
| `outbound` | `auto` | WP10.1 | `auto`, `both`, `v4` (`ipv4`) or `v6` (`ipv6`) (section 10.7) |
| `timeout_ms` | 2,000 | WP10.1 | The longest an attempt has, 100 to 30,000 (section 10.4) |
| `budget_queries` | 32 | WP10.1 | Queries sent per client query, 1 to 256 |
| `budget_restarts` | 8 | WP10.1 | CNAME and DNAME links per name, 1 to 32 |
| `budget_depth` | 6 | WP10.1 | Nesting of name-server lookups, 1 to 16 |
| `budget_ms` | 10,000 | WP10.1 | Wall clock per client query, 100 to 60,000 |
| `infra_entries` | 1,000 (Home), 10,000 | WP10.1 | Zone cuts the infrastructure cache holds, 10 to 1,000,000; server addresses at twice that |
| `infra_ttl_secs` | 900 | WP10.1 | How long a learnt lameness and a learnt need for lower case hold, 10 to 86,400 |
| `failure_cache_max_secs` | 300 | WP10.1, WP10.3 | The longest a failure is remembered, 5 to 3,600 |
| `fresh_port_per_query` | `true` | WP10.1 | A fresh source port for every exchange with an authority |
| `local_zones_except` | none | WP10.1 | Locally served zones that are resolved all the same (section 10.8) |
| `qname_minimisation` | `relaxed` | WP10.3 | `relaxed`, `strict` or `off` (section 11.1) |
| `aggressive_nsec`, `denial_entries` | `true`; 2,000 (Home), 20,000 | WP10.3 | The denial cache (section 11.2) |
| `trust_anchor_signalling`, `key_sentinel` | on except under Hardened; `true` | WP10.2 | RFC 8145 (the node signals its root key tags once a day) and RFC 8509 (the sentinel names) |
| `rfc5011_hold_down_secs` | not set | WP10.2 | The hold-downs of RFC 5011 in seconds, a test knob that the Lab profile only allows; the anchor service paces its refresh with it |

The attempts per server (3) and the fetch policy (3, 2, 1, 0) are fixed.

### 10.15 Query counts per case (M40)

The engine is tested against a scripted lab (`crates/tenko-dns/src/recurse/tests.rs`) whose zones are spread over servers of their own, so that every referral of the Internet happens: the root, the TLD `test`, `example.test` with its children, and the quirk servers. Each case of E36 starts from a primed engine with a cold infrastructure cache and records the queries sent to authorities; the table `CASES` holds the counts and the test `every_case_of_e36_ends_within_the_budget_with_its_query_count` checks them. A query is counted when it is sent to an authority server: the priming before the case is not counted, a sub-query for a name server's address is, and so is every retry of the fallback ladder (the retry without EDNS, the retry over TCP after a truncation, the retry in lower case after a 0x20 mismatch, every attempt after a timeout); a BADCOOKIE retry is not. In each failing case the resolution ends with SERVFAIL and the extended error 22, and asking the same question again sends nothing (the failure cache of section 10.3).

Since WP10.3 every case runs under the three modes of QNAME minimisation (section 11.1): relaxed (the default), strict and off.

| Case | Name asked | Answer | Queries, relaxed | Strict | Off |
|---|---|---|---|---|---|
| A name three labels down: root, TLD, zone | `www.example.test A` | NOERROR | 3 | 3 | 3 |
| A wildcard | `any.wild.example.test A` | NOERROR | 4 | 4 | 3 |
| NXDOMAIN | `nothing.example.test A` | NXDOMAIN | 3 | 3 | 3 |
| NODATA | `www.example.test AAAA` | NOERROR, no data | 3 | 3 | 3 |
| A CNAME within the zone, asked again for the target | `alias.example.test A` | NOERROR | 4 | 4 | 4 |
| A chain of two CNAME records | `short1.cname.example.test A` | NOERROR | 6 | 6 | 5 |
| A lame delegation (NS at BIND, which serves the parent) | `www.lame.example.test A` | SERVFAIL | 4 | 4 | 4 |
| A delegation whose name servers point at each other without glue | `www.loop.example.test A` | SERVFAIL | 4 | 4 | 4 |
| A CNAME loop | `loop1.cname.example.test A` | SERVFAIL | 5 | 5 | 4 |
| A chain of ten CNAME records, over the eight links | `c1.cname.example.test A` | SERVFAIL | 12 | 12 | 11 |
| A TLD whose server does not answer | `www.unreachable A` | SERVFAIL | 4 | 4 | 4 |
| A server that breaks 0x20, asked again in lower case | `www.case.quirk.example.test A` | NOERROR | 6 | 6 | 5 |
| A server that answers FORMERR to EDNS, asked again without | `www.noedns.quirk.example.test A` | NOERROR | 6 | 6 | 5 |
| A server that truncates everything, asked again over TCP | `www.tc.quirk.example.test A` | NOERROR | 6 | 6 | 5 |
| A referral with out-of-bailiwick glue, which is ignored | `www.oob.example.test A` | NOERROR | 6 | 6 | 6 |
| An answer above 1,232 octets, over TCP | `big.example.test AAAA` | NOERROR | 4 | 4 | 4 |

The counts follow from the walk; the off column is the walk of WP10.1. Minimisation costs one query wherever a label between a cut and the name is no cut: `wild.example.test` before `any.wild.example.test`, `cname.example.test` once per resolution of a chain (the engine remembers it), `quirk.example.test` before the quirk servers' zones. The scripted servers answer correctly for empty non-terminals, so strict and relaxed agree; the case of a server that does not (`www.a.b.broken.example.test`: relaxed 5 and the fallback remembered, strict 4 and NXDOMAIN, off 4) is the test `relaxed_minimisation_falls_back_for_a_server_that_denies_its_empty_non_terminals`. The plain cases are the root, the TLD and the zone (3). The scripted servers answer a CNAME on its own, without the record of its target, so each link costs one more query: 4 for one link, 5 for two, and the chain of ten stops at the ninth link (3 + 8 = 11). A server that holds the whole chain in one zone and answers it in one message is read in one query (`classify` follows a chain inside the zone). The lame delegation is those three queries plus one to BIND, whose negative answer carries an SOA of the parent. The unreachable TLD is the query to the root plus the three attempts at the silent server. The quirk cases add the one query the ladder repeats: without EDNS, over TCP, or in lower case. The out-of-bailiwick case has to look up the name server's address, because the glue is ignored: the three queries give the referral, the lookup takes two more (the TLD's referral and the answer of the server of `elsewhere.test`), and the zone's own server one: 6.

The compose lab has the same cases against a root of its own, served by a second Tenko node (`deploy/compose/lab-dns`, the round `recursion`, [its README](../deploy/compose/lab-dns/README.md)). That node serves the root, the TLD and the zones under it from one address and answers from the deepest zone it holds, so a name of its own zones costs one query after priming; a delegation to another server costs one more. The round prints one line per case under the heading M40; the three runs of 2026-10-22 (Docker in WSL, the musl image) gave the same counts each time:

| Case (row of the round) | Answer | Queries | Time |
|---|---|---|---|
| `rec.resolve`, `rec.wildcard`, `rec.dname`, `rec.chain`, `rec.nxdomain` | NOERROR or NXDOMAIN | 1 | 0.3 to 0.45 s |
| `rec.big` (TC, then TCP) | NOERROR | 2 | 0.3 s |
| `rec.lame`, `rec.nsloop` | SERVFAIL, EDE 22 | 2 | 0.3 s |
| `rec.cname.loop` | SERVFAIL, EDE 22 | 1 | 0.3 s |
| `rec.cname.ten` (eight links in the first answer, the rest in the second) | SERVFAIL, EDE 22 | 2 | 0.3 s |
| `rec.unreachable`, `rec.slow`, `rec.spoof` (three attempts that time out) | SERVFAIL, EDE 22 | 4 | 2.8 to 2.9 s |
| `rec.0x20`, `rec.formerr`, `rec.tc` (the referral, the ladder's two) | NOERROR | 3 | 0.3 to 0.4 s |
| `rec.oob` (the referral, the name server's address, the answer) | NOERROR | 4 | 0.4 to 0.5 s |

The times are dig's from the client container through `docker compose exec`, about 0.3 s of which is the exec itself. The second ask of every failing case sent no query. Priming from the lab's hints file took 1.3 ms at start (M41's priming half: under 100 ms). The measurements of resolutions per second, of the memory and of the cost of a fresh source port are WP10.5's (M36 to M41).

### 10.16 What is not built yet

| What | Package | Today |
|---|---|---|
| The REVOKE bit of RFC 5011 in Tenko's own signer | later | The validator follows a revoked key (WP10.2), but the signer never sets the bit; the lab's round `rfc5011` therefore rolls a root that BIND's tools sign |
| The command line and the rest of the UI | WP10.4 | No `tenko dns` command for the resolver. The API refuses a forwarding rule of mode `recurse` and a view's `resolution` (501), although the engine follows both when the rows exist. The Recursion page shows the status |
| QNAME minimisation, the denial cache and the bounded failure cache | WP10.3 | Every server on the path is sent the full name, and no answer is synthesised from a cached denial. The failure cache is the in-memory reference of section 10.3 |
| The measurements and the exit document | WP10.5 | No figure for throughput, memory or the cost of a fresh port per exchange |
| Special-use names on the worker | later | Locally served names (section 10.8) are answered on the runtime, after the cache and the hand-over, and the answer is cached; the allocation-free path of ADR 0009 does not answer them first |
| Other transports, other sources | not planned in this slice | Connection reuse and pipelining over TCP to authorities, encrypted transport to authorities (RFC 9539), a local copy of the root zone (RFC 8806), DNS64 and the client subnet option (RFC 7871) |

## 11. QNAME minimisation and the denial cache

This section describes what WP10.3 of the recursion plan added to the resolver of section 10: the minimising step of the engine (RFC 9156), the denial cache that answers names it can prove absent without asking anyone (RFC 8198, RFC 8020), and the bounded failure cache (RFC 9520) (DNS-34, DNS-03; [dns-recursion-plan.md](plans/dns-recursion-plan.md) sections 2.2, 2.6 and 2.10; REC-Q8 decided relaxed minimisation and the denial cache on in every profile). The code is `crates/tenko-dns/src/recurse.rs` (`Minimiser` and the walk), `crates/tenko-dns/src/cache/denial.rs` with its modules `order`, `store` and `synth`, and `crates/tenko-dns/src/cache/failure.rs`.

### 11.1 QNAME minimisation

Each step of the walk asks a cut's servers only for the labels they need: the cut's zone and one label more of the name, then one more, and so on (RFC 9156 section 3). The first four minimising steps add one label each; after them the remaining labels are spread so that at most ten steps of one walk are minimised, and the step that would reach the name asks the name itself. A minimised question carries the original type, or A for the types a server may refuse or answer from another zone at an intermediate name (DS, ANY, RRSIG, NSEC, NSEC3, OPT and the meta types), as section 2.1 of the RFC allows.

| Answer to a minimised question | What the walk does |
|---|---|
| A referral | Moves down to the delegated zone, and minimises again from there |
| An answer, NODATA, a CNAME | The name exists and is no cut: one label more of the same servers. The engine remembers the name for the infrastructure TTL (at most as many names as server addresses, the least recently used out, flushed with the infrastructure cache), so that the next walk through it, a restart for a CNAME target included, does not ask it again |
| NXDOMAIN, relaxed | Asks the same servers for the full name. When that answer is no NXDOMAIN, the server answered NXDOMAIN for a name whose descendant exists (it is not RFC 8020 clean): the zone is asked with full names for the infrastructure TTL (`infra_ttl_secs`, the cut's `minimise_fallback` slot of section 10.10) |
| A lame answer (REFUSED, SERVFAIL, FORMERR, an unusable answer), relaxed | The same: the full name of the same servers, without marking the server lame for the shorter question, and the fallback remembered when the full name works |
| NXDOMAIN, strict | The name does not exist either (RFC 8020): the resolution ends with NXDOMAIN and nothing falls back |
| A lame answer, strict | As for any question (section 10.2): the server is lame for the zone and the next one is asked |

`off` sends the full name to every server. The cache is the same in every mode: the minimised answers fill the infrastructure cache (NS sets, glue, DS states), only the final answer goes into the answer cache, and a cache hit never depends on the mode. With minimisation the root sees `test` and the TLD sees `example.test` for the name `www.nsec3.example.test`; only the zone's own servers see the full name. The cost is one query per label between a cut and the name that is no cut, once per infrastructure TTL: a name two labels below its zone's apex costs one query more than without minimisation the first time, and a CNAME chain whose links share an empty non-terminal one query more in all (section 10.15 has the counts per mode). A server that serves a parent and its child zone and answers from the child without a referral (as BIND does, and the lab's authority) hides the cut, so the resolver stays at the parent's cut and minimises through the child's apex; the memory keeps that to one extra query per name between them per infrastructure TTL.

### 11.2 The denial cache

The denial cache (`Denials`) is a per-node store beside the answer cache, per view and zone:

| What | From | Lifetime |
|---|---|---|
| The zone's SOA and its signatures | Every negative answer kept | Its TTL |
| NSEC records in canonical order (RFC 4034 section 6.1: an order key per owner whose byte order is the canonical order) | The authority section of an answer the validator called `secure` | The smallest of the record's TTL, its signatures' TTLs and original TTLs, and the time left to their expiration (RFC 4035 section 4.5) |
| NSEC3 records by hashed owner, under one salt and iteration count per zone (a change of the parameters starts the chain again) | As NSEC; a chain above the validator's insecure cap (100 iterations, RFC 9276) is not kept | As NSEC |
| The wildcard RRsets a validated expansion showed (a signature with fewer labels than its owner, RFC 4035 section 5.3.4), under the wildcard's name | The answer section of a `secure` wildcard answer | As NSEC |
| Names that do not exist in an unsigned zone (RFC 8020): the last name of the answer's CNAME chain, below the SOA's zone | An NXDOMAIN the validator called `insecure` or `indeterminate`, or that nobody validated | The negative TTL: the SOA's TTL, at most its MINIMUM |

Nothing is kept from a bogus answer, and no NSEC or NSEC3 record is kept from an answer that is not `secure`. Forwarded answers fill the cache as the engine's do. The bound is `denial_entries` (2,000 under Home, 20,000 under the others), counted in records and names; past it the least recently used sixteenth goes.

**The lookup on the worker.** For a query the answer cache has no fresh entry for, the worker looks for the closest enclosing zone the denial cache holds, under the store's read lock and without allocating, after the failure cache of section 11.4. In an unsigned zone, a cached NXDOMAIN of the name or of an ancestor below the apex answers it. In a signed zone the NSEC3 chain is tried first, then the NSEC records:

| Proof | NSEC | NSEC3 |
|---|---|---|
| NXDOMAIN | The record that covers the name, the closest encloser (the longest suffix the name shares with the record's owner or its next name) and the record that covers the wildcard at the closest encloser | Down from the apex: the deepest ancestor that has a matching record is the closest encloser and the name one label below it the next closer; the matching record, the record that covers the next closer and the record that covers the wildcard (RFC 5155 section 8.3). At most 8 hashes per lookup, in the fixed buffers of `dnssec/chain.rs` |
| NODATA | The record at the name without the type (and without CNAME); an empty non-terminal (the covering record's next name lies below the name) | The record matching the name without the type |
| Wildcard NODATA | The covering record and the wildcard's record without the type | The encloser's match, the next closer's cover and the wildcard's match |
| Wildcard answer | A cached expansion of the wildcard with the type answers under the name asked, with the record that covers the name | The same, with the record that covers the next closer |

A record whose owner is a delegation (NS without SOA) or a DNAME above the name proves nothing below it, and an NSEC3 record with the opt-out flag proves no NXDOMAIN (RFC 8198 section 4.3). DS, ANY, RRSIG, NSEC, NSEC3, OPT and the meta types are never synthesised. A lookup that finds no proof falls through to the runtime as before.

**The answer** is written into the worker's buffer: the client's id and question, RA, its RD and CD, the RCODE (3, or 0 for NODATA and the wildcard answer), AD when the records are secure and the client asked with AD or DO, the SOA in the authority section of a negative answer, and for a client with DO the NSEC or NSEC3 records of the proof with every signature (each record once). A wildcard answer carries the wildcard's records under the name asked (in the client's case), with their signatures for DO. Every TTL is the smallest left of the records used, and a negative answer's TTL is at most the SOA's MINIMUM. An answer that does not fit the client's limit is TC with the header and the question. The answer of RFC 8020 is NXDOMAIN with the SOA and AD clear. `tests/alloc.rs` binds the lookup and the synthesis for NSEC, NSEC3, the wildcard answer and RFC 8020, for clients with and without DO; a deliberate allocation in the synthesis makes it fail.

`aggressive_nsec = false` turns the lookup off; the records are still kept, so that turning it on again needs no new answers. `dns.cache.flush` (section 3.5) empties the denial cache with the answer cache; with a suffix it removes the zones at or below the suffix and, in the zones above it, the records whose owners are at or below it.

### 11.3 RFC 8020

An NXDOMAIN means that nothing exists below the name. The resolver applies it twice: the strict minimisation of section 11.1 takes an NXDOMAIN of a shorter name as the answer, and the denial cache answers a name at or below a cached NXDOMAIN of an unsigned zone without asking. The exceptions: the denied name is the last name of the answer's CNAME chain, not the name asked; the zone's apex is never denied; a signed zone answers from its NSEC or NSEC3 records, which a validating client can check, and never from the bare NXDOMAIN; and the relaxed minimisation does not trust an NXDOMAIN of a shorter name, since some servers answer it for an empty non-terminal (section 11.1).

### 11.4 The failure cache

The failure cache of section 10.3 is now `Failures`: per view, name, type and class, a resolution that ends in SERVFAIL for a cause of the servers (no reachable authority, the work budget, a network error) or an answer the validator called bogus is held for 5 seconds, doubling on each repeat while the last hold or as long again runs, up to `failure_cache_max_secs` (300). A bogus answer's entry in the answer cache lives as long as its hold. A FORMERR of the client's question is answered before the engine and never cached. The worker looks the failure up after a miss of the answer cache, without allocating, and answers SERVFAIL with the stored extended error; a bogus failure is not answered there for a client with CD, which gets the data from the answer cache or the runtime. The engine looks it up again before it resolves. The failures are spread over shards by a hash of the key, each with its share of the bound (the answer cache's `entries`), and a full shard drops its least recently used sixteenth: the cache never empties itself wholesale. The flush of the answer cache flushes it, everything or at or below a suffix. `MemFailures`, the reference of the contracts, is bounded in the same way.

### 11.5 Settings

| Key of `[dns.recursion]` | Default | Meaning |
|---|---|---|
| `qname_minimisation` | `relaxed` in every profile | `relaxed`, `strict` (never falls back; what Hardened may choose) or `off` |
| `aggressive_nsec` | `true` | The denial cache answers (RFC 8198, RFC 8020); `false` keeps filling it without answering from it |
| `denial_entries` | 2,000 (Home), 20,000 | The denial cache's bound |
| `failure_cache_max_secs` | 300 | The longest hold of a failure, 5 to 3,600 |

A node whose resolver is off still keeps a denial cache beside its answer cache, bounded at 20,000 and filled from validated forwarded answers.

### 11.6 Metrics, the query log and the status

| What | Where |
|---|---|
| Answers synthesised, by kind: `nxdomain`, `nodata` (the wildcard NODATA included), `wildcard`, `nxdomain_cut` (RFC 8020) | `tenko_dns_denial_total{kind}` |
| Questions answered from the failure cache, by the worker or the engine | `tenko_dns_failure_cache_hits_total` |
| A synthesised answer in the query log | `resolution = denial`, with `validation` `secure` (`insecure` for RFC 8020) |
| The counters since the role started: minimised queries, the retries with the full name, the zones remembered as asked whole, the synthesised answers by kind, the denial cache's entries and bound and whether it answers, the failure cache's hits and size | `ResolverCounters` of the node's `dns` role (`crates/tenko-dns/src/status.rs`, `DnsNode::resolver_counters`), for the recursion status |

### 11.7 The lab rows of E35 and M42

The round `recursion` of the compose lab (`deploy/compose/lab-dns/denial.sh`, [its README](../deploy/compose/lab-dns/README.md)) checks E35 against the lab root, with the authority node's query log and the quirk responder `quirk-ent` (a server that answers NXDOMAIN for its empty non-terminals and prints every question) as the witnesses:

| Row | What |
|---|---|
| `den.qmin` | With the node's caches flushed, `www.nsec3.example.test` (three labels below the TLD) reaches the authority once, after the minimised questions `example.test` and `nsec3.example.test` (type A, which only minimisation asks of those names). The lab's authority serves the root, the TLD and the zones from one address without referrals, so these are all questions to the root's servers |
| `den.qmin.fallback` | Relaxed: `quirk-ent` is asked `b.ent.quirk.example.test` (NXDOMAIN), then the full name, which answers; the next name of the zone goes out whole at once |
| `den.nsec`, `den.nsec.nodata` | After `nothing.example.test` (NXDOMAIN) and `api.example.test AAAA` (NODATA), `nope.example.test` is NXDOMAIN and `api.example.test MX` is NODATA, both with AD, and the authority's log has no query for them |
| `den.nsec3`, `den.nsec3.nodata` | The same in the NSEC3 zone (`b.nsec3.example.test`, `www.nsec3.example.test TXT`) |
| `den.wildcard` | After `one.wild.example.test`, `two.wild.example.test` (in the range of the same NSEC record, after `host`) is answered from the wildcard with no query |
| `den.rfc8020` | After `gone.insecure.example.test` (NXDOMAIN, unsigned), `x.gone.insecure.example.test` is NXDOMAIN with no query |
| `den.delv.nxdomain`, `den.delv.nodata` | `delv` validates the synthesised NXDOMAIN and NODATA through the node |
| `den.strict` | Strict (the node restarted): `quirk-ent` is asked `b.ent.quirk.example.test` only, and the answer is NXDOMAIN |
| `den.off.aggressive` | `aggressive_nsec = false`: the second name reaches the authority |
| `den.off`, `den.off.ent` | Off: `www.nsec3.example.test` is asked whole with no shorter question, and `quirk-ent` is asked the full name only |

The round ran twice on 2026-10-23 (Docker in WSL, the musl image built from the WP10.3 tree): 144 of 144 rows PASS each time, the 14 rows above among them. The witnesses were the same in both runs: `www.nsec3.example.test` reached the authority once after one minimised question each for `example.test` and `nsec3.example.test`, and with minimisation off once with none; `quirk-ent` was asked `b.ent.quirk.example.test` and then the full name (relaxed), then `www.c.ent.quirk.example.test` whole, `b.ent.quirk.example.test` only (strict), the full name only (off); the six names of the denial rows reached the authority 0 times, and with `aggressive_nsec = false` once. The lab's M40 lines now include the minimised questions and the validator's DS and DNSKEY queries, so they are not comparable with the figures of section 10.15.

M42 (the denial cache's effect) runs in the same round with `M42=1`: with the cache 1 to 5 authority queries per 1,000 random names under a covered NSEC or NSEC3 range, without it 1,001 to 1,005, under each minimisation mode; the procedure and the figures are in [bench/phase2-dns/results/2026-10-23-m42-denial.md](../bench/phase2-dns/results/2026-10-23-m42-denial.md).
