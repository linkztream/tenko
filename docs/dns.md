# DNS: zones, records, zone files, keys, the dns role, the forwarder and the engine

This page describes how Tenko DDI holds DNS data and answers for it: zones and their kinds, RRsets and the rules they keep, batch changes with a dry run, zone file import and export, SOA serials and the journal that zone transfers read, access lists and TSIG keys, the `dns` role that serves the zones, the forwarder for names outside them (in [dns-resolver.md](dns-resolver.md)), and the engine underneath. It is for an operator who manages zones through the API, the command line or the web UI and runs a node that answers DNS, and for a developer who builds on the zone service or the engine. It describes the zone service `tenko_dns::zone`, the role (`tenko_dns::store_feed`, `forward`, `querylog`, `status` and `tenko serve`), the engine (`crates/tenko-dns`), the model `tenko_core::dns` and the `/dns` and `/nodes/{id}/dns` routes of `tenko-api`; where this page and the code differ, the code is right. The requirements are DNS-01, DNS-07, DNS-09, DNS-11, DNS-19, DNS-24, TGL-10 and MIG-15 in [REQUIREMENTS.md](REQUIREMENTS.md); the decisions are in [ADR 0017](adr/0017-dns-data-model-and-serving-path.md) and section 2 of the [Phase 2 plan](plans/phase-2-plan.md). The contracts every Phase 2 package shares (tables, routes, codes, audit actions) are listed in [dns-contracts.md](dns-contracts.md). Views, block lists, dynamic updates and DNSSEC get their sections when their packages land.
This page describes how Tenko DDI holds DNS data and answers for it: zones and their kinds, RRsets and the rules they keep, batch changes with a dry run, zone file import and export, SOA serials and the journal that zone transfers read, access lists and TSIG keys, the `dns` role that serves the zones, the forwarder for names outside them (in [dns-resolver.md](dns-resolver.md)), and the engine underneath. It is for an operator who manages zones through the API, the command line or the web UI and runs a node that answers DNS, and for a developer who builds on the zone service or the engine. It describes the zone service `tenko_dns::zone`, the role (`tenko_dns::store_feed`, `forward`, `querylog`, `status` and `tenko serve`), the engine (`crates/tenko-dns`), the model `tenko_core::dns` and the `/dns` and `/nodes/{id}/dns` routes of `tenko-api`; where this page and the code differ, the code is right. The requirements are DNS-01, DNS-07, DNS-09, DNS-11, DNS-20, DNS-24 and MIG-15 in [REQUIREMENTS.md](REQUIREMENTS.md); the decisions are in [ADR 0017](adr/0017-dns-data-model-and-serving-path.md) and section 2 of the [Phase 2 plan](plans/phase-2-plan.md). The contracts every Phase 2 package shares (tables, routes, codes, audit actions) are listed in [dns-contracts.md](dns-contracts.md). Views have section 11; transfers, dynamic updates and DNSSEC get their sections when their packages land.

Terms used below: an **RRset** is the records of one owner name and type in one scope of a zone. A **scope** is one version of a zone's data that views choose (DNS-20); every zone has the scope `default`. The **apex** is the zone's own name. An RRset's **origin** says who owns it: `manual` (API, UI, zone file), `ipam` (the DNS actuator of IPAM), `dynamic` (RFC 2136), `transfer` (zone transfers, section 10), `dhcp` and `ad`.

Contents:

1. [Zones and kinds](#1-zones-and-kinds)
2. [Records and the RRset rules](#2-records-and-the-rrset-rules)
3. [Batch changes and the dry run](#3-batch-changes-and-the-dry-run)
4. [Zone files: import, export, limits](#4-zone-files-import-export-limits)
5. [Serials and the journal](#5-serials-and-the-journal)
6. [Access lists and TSIG keys](#6-access-lists-and-tsig-keys)
7. [Reverse zones and the IPAM link](#7-reverse-zones-and-the-ipam-link)
8. [The dns role](#8-the-dns-role)
9. [The forwarder](#9-the-forwarder)
10. [Zone transfers and NOTIFY](#10-zone-transfers-and-notify)
12. [The engine](#12-the-engine)

Section 11 is kept for the package that writes it (views); the resolver side has its own page, [dns-resolver.md](dns-resolver.md).
11. [Views, scopes and weights](#11-views-scopes-and-weights)
12. [The engine](#12-the-engine)

Section 10 is kept for the package that writes it (transfers and dynamic updates); the resolver side has its own page, [dns-resolver.md](dns-resolver.md).

All routes are under `/api/v1` and exist only while the DNS module runs (OPS-25); otherwise they answer 404 `sys.route_not_found`. Reads need the scope `dns.read`, changes `dns.write`, everything on keys `dns.keys` (section 6). Every change is committed with its audit record in one write, and every change of the DNS data appears on the event topic `dns`.

## 1. Zones and kinds

| Kind | Holds data in Tenko | Phase 2 |
|---|---|---|
| `primary` | yes | Tenko is the source of the zone |
| `rpz` | yes | a response policy zone (the policy engine is WP5.2) |
| `secondary` | yes, the copy | filled by zone transfers from `source.primaries` (section 10); the records are read-only |
| `stub` | no | the row only; it names the servers to ask (WP5.1) |
| `forward` | no | the row only; queries go to `source.primaries` (WP5.1) |

A zone has a name (the apex, not a wildcard), its scopes, a serial policy (section 5), the SOA values (`soa`: `mname`, `rname`, `refresh`, `retry`, `expire`, `minimum`, `ttl`; the SOA TTL is also the default TTL of new RRsets), a transfer policy, an update policy (named `DnsUpdatePolicy` in the OpenAPI document), a DNSSEC policy, the source servers of a secondary, stub or forward zone, and a description. A primary or RPZ zone needs at least one name server; a zone of another kind takes none. The access lists a zone's transfer or update policy names must exist.

Creating a primary or RPZ zone writes, in every scope, the apex SOA (with the first serial of the policy) and the apex NS set of the name servers. Changing a zone:

- a change of `soa` rewrites the SOA of every scope with the next serial and a journal entry;
- a new scope gets an SOA and a copy of the default scope's NS set;
- a removed scope loses its RRsets and its journal;
- the name and the kind do not change.

Deleting a zone removes its row, its RRsets and its journal in one write when they fit in one batch. A larger zone loses its row first (so the engine stops serving it at once) and its RRsets are deleted in batches right after.

A zone read carries `soa_serial` (the serial of the default scope's SOA, 0 for a zone without data), `rrsets` (in all scopes), `origins` (the RRsets per origin, sorted by origin) and `revision`, which is also the `ETag`. `PATCH` and `DELETE` take `If-Match: "<revision>"` and answer 412 when it is stale.

```
tenko dns zone create example.test --kind primary --ns ns1.example.test \
  --mname ns1.example.test --rname hostmaster.example.test --serial date_counter
tenko dns zone list
tenko dns zone get example.test
tenko dns zone delete example.test
```

```
POST /api/v1/dns/zones
{"name": "example.test", "kind": "primary", "serial": "date_counter",
 "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
 "name_servers": ["ns1.example.test"]}

201 Created
ETag: "42"
{"id": "0190d1c2-...", "name": "example.test", "kind": "primary", "scopes": [{"name": "default"}],
 "serial": "date_counter", "soa": {...}, "soa_serial": 2026101701, "rrsets": 2,
 "origins": [{"origin": "manual", "rrsets": 2}], "revision": 42, ...}
```

| Operation | Route | Scope |
|---|---|---|
| `list_dns_zones` | `GET /dns/zones` | `dns.read` |
| `create_dns_zone` | `POST /dns/zones` | `dns.write` |
| `get_dns_zone` | `GET /dns/zones/{id}` | `dns.read` |
| `update_dns_zone` | `PATCH /dns/zones/{id}` | `dns.write` |
| `delete_dns_zone` | `DELETE /dns/zones/{id}` | `dns.write` |

## 2. Records and the RRset rules

An RRset is stored with the uncompressed wire form of each record (names lowercase), its TTL, its origin and, for a dynamic update, its TSIG key. The API reads and writes the records typed (`RecordData`): A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, TLSA, SVCB and HTTPS by their fields, every other type as RFC 3597 data (`{"type": "unknown", "rtype": "TYPE65280", "data": "c0000201"}`).

The rules every write keeps (`RrSet::check`, `check_node`, `check_apex`):

- the owner is at or below the apex; no meta type; the TTL is at most 2^31 - 1;
- 1 to 4,096 records without duplicates, each valid for its type; CNAME, DNAME and SOA sets have one record;
- SOA stands at the apex only, CNAME never there, DS never at the apex; a wildcard owns no NS, SOA or DS;
- a CNAME stands alone (only RRSIG and NSEC beside it);
- an NS set below the apex is a delegation: only DS, RRSIG, NSEC and glue addresses stand beside it;
- the apex of every scope holds an SOA and an NS set;
- a TXT string longer than 255 octets is split into strings of at most 255 octets at character boundaries (DNS-24).

The list of a scope runs in canonical name order (RFC 4034: labels compared from the root down, a name before its subtree), types ascending, 1 to 1,000 per page with a cursor. Filters: `name` (owners whose name relative to the apex, or whole name, starts with the text; `@` is the apex), `type` and `origin`.

```
tenko dns record list example.test --name www
GET /api/v1/dns/zones/{id}/records?name=www&type=A&limit=100
```

Origins (plan section 2.5): API, UI and zone-file writes are `manual`. A change that would replace, shrink or delete an RRset of another origin is refused with 409 `dns.record.origin` (parameter `origin`) unless the change says `take_over`; the RRset is then `manual`, and the audit record `dns.record.change` names it (`take_over`: owner, type and former origin). The update policy's `may_replace_ipam` concerns dynamic updates (WP6.2), not the API.

## 3. Batch changes and the dry run

`POST /dns/zones/{id}/records/batch` takes a list of changes that apply together or not at all (at most 10,000):

| `op` | Does |
|---|---|
| `set` | Replaces the RRset with the records (creates it when absent) |
| `add` | Adds the records to the RRset (creates it when absent) |
| `remove` | Removes the records; an RRset left empty is deleted |
| `delete` | Deletes the RRset |

Each change names the `scope` (default `default`), the owner `name`, the `type`, the records and optionally the `ttl`: an RRset keeps its TTL when none is given, and a new RRset takes the SOA TTL. The changes run in order over the owners they touch, so a batch can delete an A set and put a CNAME at the same name. Then every changed RRset, every touched owner and the apex are checked with the rules of section 2. The SOA is not changed by a batch (it follows the zone settings): a change of type SOA is refused with `dns.record.invalid`.

The answer lists the changed RRsets with `before` and `after` (absent for a new or a deleted RRset). With `dry_run=true` nothing is written; otherwise the answer adds the new `serial` (of the default scope when the batch touched it) and the `revision`. A batch that changes nothing writes nothing and moves no serial.

```
tenko dns record add example.test www A 192.0.2.10 --ttl 300 --dry-run
tenko dns record replace example.test www A 192.0.2.10 192.0.2.11
tenko dns record delete example.test www A
```

```
POST /api/v1/dns/zones/{id}/records/batch?dry_run=true
{"changes": [
  {"op": "delete", "name": "www.example.test", "type": "A"},
  {"op": "set", "name": "www.example.test", "type": "CNAME",
   "records": [{"type": "CNAME", "target": "web.example.test"}]},
  {"op": "set", "name": "host.example.test", "type": "A", "take_over": true,
   "records": [{"type": "A", "address": "192.0.2.20"}]}]}

200 OK
{"dry_run": true, "changes": [{"scope": "default", "name": "www.example.test", "type": "A",
  "before": {...}}, ...], "serial": 2026101702}
```

| Code | Status | When |
|---|---|---|
| `dns.record.invalid` | 400 | A record or RRset breaks a rule of its type, an owner outside the zone, the SOA in a batch, no records for `set`/`add`/`remove` |
| `dns.record.conflict` | 409 | RRsets of one owner conflict (a CNAME beside data, data beside a delegation) |
| `dns.record.origin` | 409 | An RRset of another origin without `take_over` |
| `dns.zone.invalid` | 400 | A zone without data (stub, forward), a scope the zone lacks |
| `dns.zone.secondary` | 409 | A secondary zone, whose records come from transfers (section 10.7) |

## 4. Zone files: import, export, limits

### Import

`POST /dns/zones/{id}/records/import` takes `{"zone_file": "<text>", "scope": "default", "replace": false}`. The reader is `domain`'s RFC 1035 zone file scanner:

- `$ORIGIN` and `$TTL` are honoured; the zone apex is the first origin, so relative names work without a `$ORIGIN` line;
- `$INCLUDE` is refused with 422 `dns.zonefile.invalid` and its line: the import reads one uploaded file;
- `$GENERATE range lhs [ttl] [class] type rhs` (the BIND extension) is expanded, with `$`, `${offset,width,base}` (bases `d`, `o`, `x`, `X`, `n`, `N`), `\$` and `$$`, at most 65,536 records per line;
- a syntax error stops the import with 422 `dns.zonefile.invalid` (parameters `line` and `reason`).

With `dry_run=true` the answer (200) is the preview: the records per type the file brings (`types`), the RRsets the import would add, replace and, with `replace`, remove, and the losses. Without it the preview runs first (so a file that does not parse is refused at once), then the import starts as the background job `dns.import` and the answer is 202 with `job_id` and `Location: /api/v1/jobs/{id}`. The job has one step `dns.import.chunk` per 5,000 RRsets of the preview and a final step `dns.import.finish`; the steps done show the progress, and the final step's output is the report as JSON (hex in the job record): `added`, `replaced`, `removed`, `types`, the first 1,000 `losses` and `lost` (all of them), the new `serial` and the `revision`.

How the file is merged, per owner name (records of one owner that follow each other form a group):

- an RRset of the file replaces the stored RRset of its type, and one the store already holds with the same TTL and records is not written; a name the file lists again later is merged into what the import wrote before;
- the import writes `manual` RRsets and never replaces an RRset of another origin: such an RRset is a loss (`dns.zonefile.origin`);
- every RRset and every owner is checked with the rules of section 2; a broken one is a loss (`dns.zonefile.rule`);
- the apex SOA of the file is not written as a record: its values become the scope's SOA (and the zone's `soa` settings for the default scope), and its serial is kept when it is newer than the scope's serial, else the serial moves by the zone's policy, once, at the end; an import that changes no RRset and no SOA value and brings no newer serial leaves the serial and the journal alone, so importing an export into its own zone gives the same file again;
- with `replace`, the final step deletes the `manual` RRsets of the scope the import did not write, except the apex SOA and, when the file has no apex NS set, the apex NS.

The losses: a record of a class other than IN (`dns.zonefile.class`), an owner outside the zone (`dns.zonefile.outside_zone`), a name or data the model refuses, such as a name outside its character set (`dns.zonefile.data`), an SOA that is not the apex SOA or a second one (`dns.zonefile.soa`), and the two above.

The chunks do not expect the versions of what they replace: a change made while an import runs may be overwritten by it. When a step fails, or the controller restarts and the staged file is gone (`dns.job.import_missing`), the chunks written so far stay and the job ends rolled back with the error; importing the same file again completes the zone.

```
tenko dns import example.test example.test.zone --dry-run
tenko dns import example.test example.test.zone --replace
```

### Export (MIG-15)

`GET /dns/zones/{id}/records/export?scope=default` answers the zone file as `text/dns`:

```
$ORIGIN example.test.
$TTL 3600
@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026101702 3600 900 1209600 300
@ 3600 IN NS ns1.example.test.
host-1 300 IN A 198.51.100.1
mail 300 IN MX 10 mx.example.test.
txt 300 IN TXT "hello world" "second"
www 600 IN A 192.0.2.10
www 600 IN A 192.0.2.11
```

The apex SOA comes first, then every RRset in canonical name order with the types ascending, one record per line: the owner relative to the apex (`@` for the apex), the TTL, `IN`, the type and the data in presentation format with absolute names, the records of an RRset in canonical order (by wire form). The same data always gives the same bytes, and a file the export wrote imports and exports to the same bytes. Every export writes the audit record `dns.zone.export`.

```
tenko dns export example.test --file example.test.zone
```

### Limits

| Limit | Value |
|---|---|
| Zone file size | 1 GiB (the request body) |
| Records per `$GENERATE` line | 65,536 |
| RRsets per import chunk | 5,000 |
| Losses listed in a report | 1,000 (all are counted) |
| An import that leaves one journal entry | one chunk and at most 10,000 changed records; a larger import resets the scope's journal |

The import keeps the uploaded text and the scanner's copy in memory while it runs (on the controller that took the request) and one chunk of RRsets at a time; it never holds the parsed zone.

| Operation | Route | Scope |
|---|---|---|
| `list_dns_records` | `GET /dns/zones/{id}/records` | `dns.read` |
| `change_dns_records` | `POST /dns/zones/{id}/records/batch` | `dns.write` |
| `import_dns_zone_file` | `POST /dns/zones/{id}/records/import` | `dns.write` |
| `export_dns_zone_file` | `GET /dns/zones/{id}/records/export` | `dns.read` |

## 5. Serials and the journal

### Serial policies (DNS-07)

| Policy | First serial | Next serial |
|---|---|---|
| `unixtime` | the time in seconds | the time when it is newer than the current serial, else plus one |
| `counter` | 1 | plus one |
| `date_counter` (default) | today's `YYYYMMDD01` | today's `YYYYMMDD01` when it is newer, else plus one (after `nn` = 99 the serial moves into the next day's numbers) |

Serials compare in serial number arithmetic (RFC 1982), so a serial always moves forward, also across the wrap. The serial of a scope moves once per write that changes the scope: a batch, an SOA change, an import (at its end).

### The journal

Every serial step of a scope leaves one entry in `dns.journal`, in the same write as the change: the serial before and after, the time, and the records removed and added. `removed` starts with the old SOA record and `added` with the new one, in the order an IXFR answer carries them (RFC 1995, used by zone transfers in WP6.1). An entry's key is the zone, the scope and the store revision the change was planned against, which grows with every step of a scope.

The journal is bounded per scope: 1,000 entries and 30 days. Every write drops, in the same batch, the oldest entries beyond the count and those past the age (at most 32 at a time, so a backlog shrinks over the next writes). A large import resets the journal of its scope, and removing a scope or a zone removes its journal. A secondary that asks for a serial older than the first entry gets a full transfer (AXFR).

`GET /dns/zones/{id}/journal?scope=default` lists the entries of a scope, newest first, with the serials, the time and the counts of records added, replaced (an owner and type with records both removed and added) and removed, the SOA not counted.

| Operation | Route | Scope |
|---|---|---|
| `list_dns_zone_journal` | `GET /dns/zones/{id}/journal` | `dns.read` |

## 6. Access lists and TSIG keys

### Access lists

An access list has a unique name (1 to 64 characters, compared without case), at most 1,000 entries and a description. An entry is a prefix (`{"kind": "prefix", "prefix": "192.0.2.0/24"}`), a TSIG key (`{"kind": "key", "name": "transfer.example.test"}`) or `any`, each optionally `"deny": true`; the first entry that matches decides, and no match refuses. Zones name lists in their transfer policy (`transfer.allow`) and update policy (`update.allowed`), views as their recursion access list ([section 11](#11-views-scopes-and-weights)); a list a zone or a view names cannot be deleted (409 `dns.acl.in_use`, parameter `by`). A list read carries `used_by` (`zone:<name>`, `view:<name>`) and its revision as the `ETag`.

```
tenko dns acl create secondaries --entry 192.0.2.0/24 --entry key:transfer.example.test --entry any,deny
```

| Operation | Route | Scope |
|---|---|---|
| `list_dns_acls` | `GET /dns/acls` | `dns.read` |
| `create_dns_acl` | `POST /dns/acls` | `dns.write` |
| `get_dns_acl` | `GET /dns/acls/{id}` | `dns.read` |
| `update_dns_acl` | `PATCH /dns/acls/{id}` | `dns.write` |
| `delete_dns_acl` | `DELETE /dns/acls/{id}` | `dns.write` |

### TSIG keys

A TSIG key (RFC 8945) has a name (a DNS name, as the peers know it), an algorithm (`hmac-sha256` by default, `hmac-sha384`, `hmac-sha512`, `hmac-sha1` for peers that know nothing better) and a description. Its secret is generated with the length of the algorithm's hash (32, 48, 64 or 20 octets) or imported from base64 (16 to 1,024 octets), and stored in the vault as a system secret (purpose `dns.tsig`, owned by the key); the row in `dns.keys.meta` holds only its reference. The secret appears once, in the answer of the create, and is never shown again: Tenko uses it to sign and verify transfers, NOTIFY and updates. In Phase 5 a `dns` node receives it through node sync under the role purpose `tsig`.

Every action on keys needs `dns.keys` (the administrator's role); creating and deleting a key also needs an interactive session, so a personal API token cannot change keys. Deleting a key deletes its secret; an access list or a zone that still names the key matches nothing for it.

```
tenko dns key create transfer.example.test --algorithm hmac-sha256
tenko dns key list
tenko dns key delete transfer.example.test
```

```
POST /api/v1/dns/keys
{"name": "transfer.example.test", "algorithm": "hmac-sha256"}

201 Created
{"key": {"id": "...", "name": "transfer.example.test", "algorithm": "hmac-sha256", "created": {...}},
 "secret": "q7v3...base64...="}
```

The key writes are proposed with their audit record (`dns.key.create`, `dns.key.delete`) but not as inline jobs: their batch holds the vault envelope, which a job record would keep after the key is deleted (the operator secrets of the vault are written the same way).

| Operation | Route | Scope |
|---|---|---|
| `list_dns_keys` | `GET /dns/keys` | `dns.keys` |
| `create_dns_key` | `POST /dns/keys` | `dns.keys` |
| `get_dns_key` | `GET /dns/keys/{key}` | `dns.keys` |
| `delete_dns_key` | `DELETE /dns/keys/{key}` | `dns.keys` |

| Code | Status | When |
|---|---|---|
| `dns.acl.not_found` | 404 | No such access list |
| `dns.acl.in_use` | 409 | A zone names the access list |
| `dns.key.not_found` | 404 | No such key |
| `dns.key.exists` | 409 | A key of this name exists |
| `sys.invalid_value` | 400 | An access list name that is invalid or taken; a key name or secret that is invalid |

## 7. Reverse zones and the IPAM link

IPAM keeps the address and reverse records of its intent in the zones Tenko serves (DNS-22, IPAM-13, plan sections 2.5 and 2.6). The DNS actuator in `tenko_ipam::dns` plans them from the intent and writes them through the zone service of section 3 with the origin `ipam`; the reconciler runs it after its proposals, and the move step `ipam.move.dns` runs it for one device ([moves.md](moves.md) section 4). The settings and the findings are in [reconciliation.md](reconciliation.md) section 10.

### What an address gets

An address is published when it is live, has a DNS name and is not `planned` (an address in flight in a move is the exception: once the move's DNS step has started, its new address replaces the old one). Its name gets an A or AAAA record in the zone Tenko serves for it: the longest apex among the primary zones the name falls under, unless an NS set inside that zone (a delegation) covers the name. Its address gets a PTR record pointing to the name, in the RFC 2317 zone that covers it when Tenko serves one, else at the plain reverse name in the longest reverse zone. Several addresses with one name make one RRset with several records; a name in no zone is listed and left to the DNS servers that hold it, and its PTR record is still written when Tenko serves the reverse zone. New RRsets take the zone's default TTL.

```
GET /api/v1/dns/zones/{id}/records?name=printer
{"items": [{"scope": "default", "name": "printer.example.test", "type": "A", "ttl": 3600,
  "records": [{"type": "A", "address": "192.0.2.15"}], "origin": "ipam", ...}], ...}
```

### Reverse zones per prefix

A network prefix has the setting `dns_reverse`: `managed` creates and keeps its reverse zones, `off` keeps none, and absent (the default, P2-Q11) means `managed` when the tenant of the prefix's VRF has a forward zone in Tenko (a primary zone outside `arpa` of that tenant, or one without a tenant for the default tenant), else `off`. It is set with `PATCH /prefixes/{id}` (`{"dns_reverse": "off"}`; `null` returns to the default). Supernets have no reverse zones.

| Network | Reverse zones |
|---|---|
| IPv4 /0 to /24 | one per octet boundary at or below the prefix length: a /24 is `2.0.192.in-addr.arpa`, a /22 four /24 zones, a /12 sixteen /16 zones |
| IPv4 /25 to /32 | the RFC 2317 zone `<first>/<len>.<octet>.<octet>.<octet>.in-addr.arpa`, such as `64/26.2.0.192.in-addr.arpa` |
| IPv6 /0 to /124 | one per nibble boundary at or below the prefix length: a /48 is one zone of 12 nibbles, a /62 four zones of 16 nibbles |
| IPv6 longer than /124 | none |

A prefix length off the boundary rounds up, so the zones cover the prefix and nothing outside it. A new reverse zone is a primary zone whose SOA values, serial policy and name servers are copied from the longest reverse zone above it in Tenko, else from the tenant's first forward zone, else from the first forward zone; its `reverse_of` names the prefix (read only in the zone's answer). A zone of the same name that an operator created by hand is adopted: the actuator sets its `reverse_of` and keeps its PTR records. When two prefixes cover one zone, the shorter one keeps it.

Deleting the prefix or switching its setting off leaves the zone and its records in place; the actuator stops writing there and the finding `ipam.reconcile.dns_reverse_orphaned` says so. A reverse zone that belongs to no prefix (no `reverse_of`) is still written to, like any forward zone.

### RFC 2317

The PTR record of an address in an RFC 2317 block is written in the block's zone as `<last octet>.<block zone>` (`70.64/26.2.0.192.in-addr.arpa`). When Tenko serves the parent zone (the zone that holds the names of the /24), the actuator writes there, with the origin `ipam`, the delegation (an NS set at the block's apex with the block zone's name servers) and the CNAME of every address of the block (`70.2.0.192.in-addr.arpa CNAME 70.64/26.2.0.192.in-addr.arpa`). When it does not, the finding `ipam.reconcile.dns_delegation` lists the lines to add to the parent where it is served:

```
64/26.2.0.192.in-addr.arpa. IN NS ns1.example.test.
$GENERATE 64-127 $.2.0.192.in-addr.arpa. IN CNAME $.64/26.2.0.192.in-addr.arpa.
```

`$GENERATE` is BIND's form; on a server without it, one CNAME per address of the block.

### The origin rule from the IPAM side

The actuator changes only RRsets of the origin `ipam`; the zone service refuses anything else (`dns.record.origin`). An RRset IPAM wants that another origin holds with other data (a person's record, a CNAME at the name, data beside a CNAME IPAM wants) stays as it is and is proposed as `ipam.reconcile.dns_record_held`; one that holds the same data is left alone. A person who changes an `ipam` RRset through the API takes it over (`take_over`, it becomes `manual`) and gets the same proposal; a person who deletes one sees it written again by the next run, audited as `dns.record.actuate` by `system:reconciler`. An `ipam` RRset whose address lost its name or its intent is deleted, or with the orphan rule `propose` kept and proposed (`ipam.reconcile.dns_orphaned_record`).

Every batch of the actuator is one write per zone (at most 10,000 RRsets, so a larger change splits by owner), moves the zone's serial once by its policy, leaves one journal entry and is audited as `dns.record.actuate`. A zone or batch that fails is reported in the reconciler's run (`dns.failures`) and tried again at the next run.

### Findings

| Rule | Kind | When |
|---|---|---|
| `ipam.reconcile.dns_no_zone` | orphaned intent | DNS names of intent under no zone Tenko serves (or under a delegation inside one), listed with their addresses; only while Tenko serves at least one forward zone |
| `ipam.reconcile.dns_record_held` | conflict | An RRset IPAM wants is held by another origin with other data |
| `ipam.reconcile.dns_orphaned_record` | orphaned intent | An `ipam` RRset without intent, with the orphan rule `propose` |
| `ipam.reconcile.dns_delegation` | orphaned intent | The RFC 2317 delegation and CNAMEs to add to a parent zone Tenko does not serve |
| `ipam.reconcile.dns_reverse_orphaned` | orphaned intent | A reverse zone of a prefix that is gone or whose setting is `off` |
| `ipam.reconcile.dns_reverse_no_servers` | orphaned intent | A managed prefix whose reverse zone cannot be created: no zone in Tenko has name servers to copy |

The findings carry no commands: a person resolves them in the zones or the intent. They expire when the cause is gone.

### Limits

- Reverse names ignore the VRF: two VRFs with one address give one PTR RRset with both names.
- Every run reads the `ipam` RRsets of every zone that has any (the origin counters tell which), and the A, AAAA and PTR records of every primary zone for the observations; zones of millions of records make runs slower.
- The actuator's writes are not fenced with the leader epoch; a deposed leader checks before it writes, and the next leader's run corrects what a late write left.
- The switch `dns_actuator` and the orphan rule are reconciler settings without a control on the settings page yet (the modules page of WP5.5).

## 8. The dns role

The `dns` role answers queries for the zones in the store. In Phase 2 it runs in the controller's own process (plan section 2.10, [ADR 0004](adr/0004-single-binary-roles.md)): `tenko serve --roles controller,dns` (or `all`) on a node whose DNS module is on. A `dns` node of its own, fed through node sync without a controller in the process, comes with Phase 5; `--roles dns` without `controller` is refused (exit status 2), and so is `dhcp`, which is reported and skipped on a controller node. A node without the role, or with the DNS module off, starts nothing of it and runs as before.

### Start and stop

The role is the last start step of `tenko serve`, `dns` (step 14 of 14), after the API is up. On a node without the role the step logs why it has nothing to do (the role is not on the node, or the DNS module is off). Otherwise, in this order:

1. The engine's metric families join the process registry (`tenko_dns_queries_total`, `tenko_dns_query_duration_seconds`).
2. The role's derived index joins the store (below): the store builds the first image of the `dns` tables from a local read, and the catalog (the index, the views and the forwarding rules, section 12.3) is built from it off the async threads.
3. The query log writer starts when `[dns.log] enabled` is set, and the forwarder with its cache (section 9).
4. The server binds every listen address for UDP and TCP, then starts its workers: the node answers only from a complete index. A listen address that cannot be bound (port 53 without the capability, or held by another DNS server) fails the start with `start.dns.bind`, and the process stops as for any other start step.
5. The catalog's writer follows the store from then on.

The step's log line names the zones and RRsets, the revision, the listeners, the workers and the socket layout, the forwarder and the query log; `tenko serve` prints `dns role answering on <addresses> (UDP and TCP), <n> zone(s) at revision <r>, ...` below its ready line. When the process stops, the role stops first: the listeners close, the queries in hand are answered, the writer and the forwarder end and the query log is flushed, before the leader services, the job runner and the store; the log says `dns role stopped`.

### The feed: from the store to the index

The role reads its rows through one `ZoneFeed` (`tenko_dns::store_feed`, ADR 0017): a derived index of the store named `dns.serving` over the tables of the `dns` node role (every `dns.*` table but `dns.sign_state`). The engine never holds a store handle.

- **The first image** is built by the store at registration from a local read view, all tables at one revision, before the role listens.
- **Changes**: the store hands every change set that touches those tables to the index, in revision order, on its apply path, before the write returns to the API. The index looks the changed rows up at that revision and queues their stored bytes (nothing more happens on the apply path); the feed decodes them, and the catalog's writer applies them as one delta (`Delta { from, to, changes }`) and swaps the new catalog in. Change sets that queue up while the writer is busy reach it as one delta of up to 100,000 rows. A change set that cannot be read or decoded makes the feed read a whole image instead, so no change is skipped. A change set that touches no `dns` table does not reach the role, so a delta runs from the revision of the previous `dns` change to its own.
- **A snapshot install**: when the store replaces its state from a snapshot (a controller that fell far behind), it rebuilds its derived indexes; the role's index hands the new image over as one reset, which the writer builds aside and swaps whole, so answers never stop (M1). A delta that does not follow the revision held makes the writer read a fresh image from the store.
- **Lag**: the status reports how many revisions the index is behind the newest `dns` change of the store. A batch of 1,000 RRsets through the API is answered on the first query after the API answered (`crates/tenko/tests/acceptance_dns.rs` asks for under one second).

If the feed fails, the role keeps answering from the rows it holds (OPS-02) and logs the error.

### Settings

The `[dns]` section of `tenko.toml` ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)); every key has a default, and `tenko config check` validates the section. Environment variables override the file as for every section: `TENKO_DNS__LISTEN=192.0.2.53:53,[2001:db8::53]:53`, `TENKO_DNS__FORWARDERS=192.0.2.1,192.0.2.2`, `TENKO_DNS__UDP__SOCKET=shared`, `TENKO_DNS__LOG__ENABLED=true`.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `["0.0.0.0:53", "[::]:53"]` | Addresses for UDP and TCP; an IPv6 address is bound IPv6-only. A wildcard address answers from the address the host's routing picks: on a host with more than one address on a network, list each address (section 12.11) |
| `workers` | 0 (one per CPU) | UDP workers per listen address, 0 to 256 |
| `cookies` | `on` | DNS cookies: `on`, `required` or `off` (section 12.5) |
| `udp.socket` | `auto` | `reuseport` (a socket per worker, Linux only), `shared` (one socket per address), or `auto` (`reuseport` on Linux, `shared` elsewhere) |
| `udp.recv_buffer`, `udp.send_buffer` | 8388608 | Socket buffers in octets; 0 keeps the system's |
| `tcp.max_connections`, `tcp.per_client`, `tcp.idle_secs` | 1000, 10, 10 | The TCP limits of section 12.6 |
| `edns.udp_size` | 1232 | The server's EDNS UDP size, 512 to 4096 |
| `forwarders`, `forward_timeout_ms`, `forward_retries`, `upstream_ca` | none, 2000, 2, none | The default forwarder and the upstreams' budget and CA ([dns-resolver.md](dns-resolver.md) section 4.5) |
| `cache.*` | | The cache ([dns-resolver.md](dns-resolver.md) section 3) |
| `log.enabled` | `false` | The query log of this node |
| `log.path` | `<data_dir>/dns/querylog` | The directory of its files |
| `log.format` | `jsonl` | JSON lines; `dnstap` is refused until it is written (WP5.4) |
| `log.days`, `log.size_mb` | 7, 256 | Retention by age (1 to 365 days) and by size (1 to 102,400 MiB) |
| `log.sample` | 1 | Log one query in N |
| `log.pseudonymise` | `true` | Replace client addresses with a keyed hash whose key changes every day |

The settings are read at start; a change needs a restart of the node.

### Status

`GET /api/v1/nodes/{id}/dns` (scope `dns.read` and read on the node) is the role's report `dns.status`:

| Field | Meaning |
|---|---|
| `serving` | The role answers queries |
| `revision`, `lag` | The store revision of the rows the index holds; revisions between the newest `dns` change of the store and the index |
| `zones`, `rrsets` | Zones served; RRsets in the bases of the index (an RRset changed since its zone's base was built counts once the base is rebuilt, section 12.3) |
| `listeners` | Each address with its transport and, for UDP, its workers |
| `socket_mode`, `udp_workers`, `tcp_open`, `tcp_refused` | The worker layout of section 12.8: per UDP worker its address, socket and counters (received, sent, dropped, forwarded, receive and send errors) |
| `cache_entries`, `cache_bytes`, `cache_hits`, `cache_misses`, `cache_hit_ratio`, `cache_stale` | The cache ([dns-resolver.md](dns-resolver.md) section 3.6) |
| `problems` | Stub zones whose name servers could not be learnt, views whose recursion access list does not exist |
| `started` | When the role started |

In Phase 2 only the controller that runs the role answers; another node answers 409 `dns.node.not_dns`, an unknown one 404 `cluster.node.not_found`. `GET /api/v1/system/status` lists `dns` among the node's `roles` while the role runs, and carries the warning `dns.role.not_serving` when the role has stopped answering or `dns.role.lagging` when its index is more than 1,000 revisions behind the store; the cluster page shows these warnings with the others.

### Commands

The cache flush and the query log read are node commands (`docs/node-sync.md` section 5) of the kinds `dns.cache.flush`, `dns.log.read` and `dns.stats` (`tenko_dns::status`). On the single node the role executes them in place and the API records each as a row of `cluster.node_commands` in the state it reached (`done`, `failed` or `rejected`, with the detail), through an inline job; Phase 5 sends the same kinds over the command stream to a remote `dns` node without changing the routes. The leader's housekeeping removes finished commands after 7 days.

| Route | Kind | What it does |
|---|---|---|
| `POST /api/v1/nodes/{id}/dns/cache/flush?suffix=` (scope `dns.write`) | `dns.cache.flush` | Answers 202 with the command id: the cache is emptied, or the names at or below `suffix`, and the detail says how many entries went; the flush is audited (`dns.cache.flush`) |
| `GET /api/v1/nodes/{id}/dns/cache?suffix=&view=&limit=&cursor=` (scope `dns.read`) | `dns.cache.list` | A page of what the cache holds in canonical name order, with the cursor of the next page; every read is audited (`dns.cache.read`), see [dns-resolver.md](dns-resolver.md) section 3.7 |
| `GET /api/v1/nodes/{id}/dns/log?cursor=&limit=&qname=` (scope `dns.read`) | `dns.log.read` | A page of the query log, newest first: up to `limit` lines (1 to 1,000, default 100) whose query name starts with `qname`, and the cursor of the next page. 409 `dns.node.not_dns` when the node's query log is off |
| none | `dns.stats` | The counters of the workers, the forwarder and its cache, and the query log in the command's detail, for the remote path of Phase 5 |

### The query log

Per node and off by default (plan section 2.9, TGL-15), never written through the store. On the query path an entry is copied into a ring of 8,192 fixed-size slots (no allocation, a short lock); a full ring drops the entry and counts it. A writer thread empties the ring every 100 ms into JSON lines in `log.path`, one segment file `queries-<microseconds>.jsonl` at a time, flushed after each batch:

```json
{"at":"2026-10-17T12:00:00.123456Z","client":"p:3f2a9c0d81b7e645","transport":"udp","qname":"www.example.test","type":"A","rcode":0,"cached":false,"duration_micros":38}
```

`client` is the address, or with `log.pseudonymise` (the default) `p:` and 16 hexadecimal digits of an HMAC-SHA-256 of the address under a random key that is replaced at midnight UTC and never written down: one client keeps its pseudonym for a day only. `log.sample` keeps one query in N. A segment holds at most a sixteenth of `log.size_mb` (1 to 8 MiB); segments older than `log.days` go first, then the oldest while the directory holds more than `log.size_mb`; the newest segment always stays. Queries answered by the forwarder are logged when their answer is sent. Setting `log.enabled = false` and restarting the node is the kill switch. dnstap frame streams are WP5.4.

### Port 53 and the platforms

Binding port 53 needs `CAP_NET_BIND_SERVICE` on Linux (the systemd unit grants it), nothing on Windows, and in a container the capability or a published port. A resolver that already holds port 53 on the host (systemd-resolved's stub, dnsmasq, the Windows DNS server) must be moved off it, or the role listens on another address. [`deploy/README.md`](../deploy/README.md) has the steps for each platform and the firewall.

## 9. The forwarder

Names outside the zones a node serves go to the forwarder of the resolver side: forwarding rules by longest suffix and view, stub zones, the default forwarder of `[dns] forwarders`, the recursion access list of each view, the cache with serve-stale and prefetch, and upstreams over plain DNS, DoT and DoH with health, round-trip choice, random source ports and 0x20. [dns-resolver.md](dns-resolver.md) describes all of it (sections 1 to 4). The plain forwarder of Slice 4 (P2-Q16) that stood here was replaced by it in WP5.1, behind the same `ForwardSink` and `Upstream` traits (`tenko_dns::forward`, `tenko_dns::upstream`).

## 10. Zone transfers and NOTIFY

Tenko moves zones to and from other servers with the standard mechanisms: AXFR (RFC 5936) and IXFR (RFC 1995) to copy a zone, NOTIFY (RFC 1996) to say that it changed, TSIG (RFC 8945) to authenticate both, XoT (RFC 9103) to carry them over TLS, and catalog zones (RFC 9432) to hand over the list of zones itself (DNS-09, DNS-19, TGL-10). The same mechanism serves a BIND or Windows DNS server that copies a zone from Tenko, a Tenko node that copies a zone from one of them, and the migration of zones (MIG-02). The code is `tenko_dns::tsig`, `tenko_dns::xfr` (the transfer path and NOTIFY) and `tenko_dns::zone::secondary` (the secondary service); the routes are in `tenko-api` (`routes/dns/transfer.rs`) and the commands in `tenko` (`client/dns_transfer.rs`). In Phase 2 all of it runs in the controller's own process, beside the `dns` role of section 8.

### 10.1 The transfer policy and the access lists

A primary zone has a transfer policy, `transfer`:

| Field | Default | Meaning |
|---|---|---|
| `allow` | none | The access lists (section 6) whose clients may transfer the zone. None means nobody |
| `notify` | none | The servers told when the serial changes: `address`, `port` (default 53) and the TSIG `key` that signs the NOTIFY |
| `require_tsig` | `true` | A transfer must be signed with a key that an access list names |
| `xot` | `false` | A transfer is served over TLS only |

```
PATCH /api/v1/dns/zones/{id}
{"transfer": {"allow": ["0190d1c2-..."], "require_tsig": true, "xot": false,
              "notify": [{"address": "192.0.2.54", "port": 53, "key": "transfer.example.test"}]}}
```

A request for AXFR or IXFR is checked in this order, and the first failure answers:

1. The message must parse. When it carries a TSIG record, the key must be known and the MAC and the time must verify (section 10.2); a failure answers NOTAUTH (RCODE 9) with the TSIG error.
2. A class other than IN is REFUSED.
3. A name that is not the apex of a zone this node serves is NOTAUTH.
4. The policy decides, and a failure is REFUSED (RCODE 5): the zone has no `allow` list; `xot` is set and the connection is not TLS ended by this node; or no list allows the client. A list allows a client when its first matching entry is not a `deny`; an entry matches by prefix, by the TSIG key of the request, or as `any`. With `require_tsig` the request must also be signed with a key that an allowing `key` entry of the zone's lists names, so a client inside the allowed prefix but without the key is refused.
5. A secondary zone that holds no copy yet, or whose copy has expired, answers SERVFAIL.

A refusal of a signed request is signed. The scope that is transferred is the one the client's view chooses (DNS-20), as for a query. `require_tsig` is on by default and the lists are empty by default, so a new zone transfers to nobody.

### 10.2 TSIG on the wire

The algorithms are `hmac-sha256` (the default), `hmac-sha384`, `hmac-sha512` and, for peers that know nothing better, `hmac-sha1`. The fudge is 300 seconds, the value RFC 8945 recommends, both for what Tenko signs and for what it accepts. A request is verified in the order of RFC 8945 section 5.2:

| Check | Failure | Answer |
|---|---|---|
| The key is known and is the one the algorithm names | BADKEY (17) | NOTAUTH, the TSIG record with an empty MAC |
| The MAC verifies (a MAC shorter than half the hash or 10 octets is not accepted) | BADSIG (16); FORMERR for a short MAC | NOTAUTH with an empty MAC; FORMERR |
| The time signed is within the fudge | BADTIME (18) | NOTAUTH, signed, with the server's time in Other Data |

An answer of several messages (AXFR, IXFR) is signed message by message in the MAC chain of RFC 8945 section 5.3.1: the first covers the request's MAC, and each later one covers the previous MAC, the messages since and the timers. Tenko signs every message it sends. When Tenko verifies an answer (the transfer of a secondary zone) it accepts up to 99 unsigned messages between two signed ones, as the RFC lets a server send them, and requires the last message to be signed. A TSIG-signed SOA query, which a secondary sends to check the serial, is answered and signed by the transfer path; the resolver answers every signed query NOTAUTH (section 12.4).

The keys are the TSIG keys of section 6: the row in `dns.keys.meta` and the secret in the vault, read through the zone service. The transfer path holds them in a keyring that it reads without a lock, and verifying or signing allocates nothing once a key is resolved. Both sides of a transfer need the same name, algorithm and secret: create the key on one side and import the secret on the other (`POST /dns/keys` takes `secret`, section 6).

### 10.3 AXFR and IXFR out

The transfer path takes the messages AXFR, IXFR, NOTIFY and a signed SOA query before the resolver does; `tenko_dns::xfr::classify` decides from the header and the type of the question alone. It answers over TCP on the `[dns] listen` ports and over the DoT listener (section 10.4). Over UDP it answers NOTIFY, a signed SOA query, and IXFR with the SOA only (RFC 1995 section 2, which tells the client to ask again over TCP); AXFR over UDP is refused.

- **AXFR** is the SOA, every other RRset in canonical order (section 4), and the SOA again. A message holds at most 16 KiB, repeats the question and compresses owner names against it.
- **IXFR** compares the serial in the request with the zone. A client that is current gets the single SOA. A client whose serial is in the journal of the scope (section 5) gets the steps from its serial to the served one: for each step the old SOA, the records removed, the new SOA and the records added, then the current SOA. Any other client gets the zone in AXFR form.
- A secondary zone that Tenko holds transfers on to its own secondaries from its own journal (section 10.6), so a chain of Tenko nodes, or of other servers, carries IXFR.
- Every transfer is audited and counted (section 10.10).

### 10.4 XoT

Zone transfers over TLS (RFC 9103) use the DoT listener of [dns-resolver.md](dns-resolver.md) section 7: `[dns.tls] dot = true`, by default port 853 on each `[dns] listen` address or the addresses of `dot_listen`, ALPN `dot`, and the certificate of the node (the internal CA's, an imported one, or the DNS-only certificate). XoT is served only where the node ends TLS itself. A node with `behind_proxy = true` receives plain DNS from the proxy and refuses a zone that has `xot`. The access rules and TSIG are the same as over TCP, and a zone with `xot` refuses TCP on port 53 (REFUSED), so a `dig AXFR` without `+tls` fails.

A secondary zone sets `xot` on the primary. The port is 853 when `port` is 53 (the default) and the given port otherwise. Tenko checks the primary's certificate against the system roots or against the CA file `[dns] upstream_ca` (the setting of the forwarder, [dns-resolver.md](dns-resolver.md) section 4.5), for the name `tls_name` of the primary, or its address when `tls_name` is absent. A lab or internal CA therefore goes into `upstream_ca`, and the primary's certificate must carry the `tls_name` (or the address) as a subject alternative name.

### 10.5 NOTIFY out and in

**Out.** The leader service `dns.notify` follows the store's commits of the RRsets. A commit that writes a zone's SOA marks the zone, because every change set of the zone service moves the serial in the same write. For a marked zone the service:

1. waits 250 ms, so that a burst of changes becomes one NOTIFY;
2. waits until the `dns` role of the process serves that commit, so that the SOA query a secondary sends on receiving the NOTIFY sees the new serial;
3. reads the serial and sends one NOTIFY to each target of `transfer.notify`, over UDP, signed with the target's `key` when it has one;
4. waits 2 seconds for the answer, and sends the NOTIFY again after 15, 30, 60 and 120 seconds if none came (five attempts in all). A newer serial meanwhile replaces the one being retried.

It applies to primary zones and to secondary zones: a copy that changed notifies its own targets.

**In.** A NOTIFY for a secondary zone is accepted over UDP or TCP when it comes from the address of one of the zone's primaries and, when that primary has a `key`, is signed with it. It is acknowledged (signed when the request was) and refreshes the zone at once; a NOTIFY that names the serial already held is ignored. Any other NOTIFY is answered REFUSED.

### 10.6 Secondary zones

A zone of kind `secondary` is a copy of a zone on one or more primaries, named in `source.primaries` (`address`, `port`, `key`, `xot`, `tls_name`) and tried in order. The leader service `dns.transfer` keeps it fresh on the timers of the SOA it holds:

| Moment | When |
|---|---|
| First refresh | At once, when the service starts or first sees the zone |
| Refresh | After the SOA's `refresh` seconds |
| Retry | After the SOA's `retry` seconds while every primary fails (at most 60 seconds before the first copy exists) |
| NOTIFY | At once, from a primary (section 10.5) |
| Transfer now | At once, from the API (section 10.9) |
| Expire | After the SOA's `expire` seconds without a success: the records of the copy are removed and the zone answers SERVFAIL until the next transfer |

A refresh sends IXFR with the copy's SOA. A primary that answers with the single current SOA leaves the copy as it is. A primary that answers NOTIMP or FORMERR, or with a newer single SOA, is asked for AXFR on a new connection, and a zone without a copy is asked for AXFR at once. With a `key` the request is signed and the answer must verify in the MAC chain; with `xot` the connection is TLS (section 10.4).

The result is one change set through the store, fenced with the leader's epoch like every write of a leader service:

- the RRsets of the transfer replace those of the copy and have the origin `transfer` (section 2); the SOA keeps the serial as received;
- the journal gets one entry with the net change (the SOA pair, the records removed, the records added) when the change has at most 10,000 records and a copy existed before; a first transfer or a larger change resets the journal, so the secondaries of this zone get AXFR;
- the audit record `dns.zone.transfer_in` names the zone, the kind (`axfr` or `ixfr`), the primary, the serial, the serial before, the number of records, and whether the journal got an entry or was reset;
- a change of more than 20,000 RRsets is written in chunks with the SOA last, which is not one commit (section 10.12).

Because the copy is written through the store, the index of the `dns` role follows it like any other change and the zone is served as soon as it is written. The SOA and the name servers of a secondary zone come from the primary and are read-only in the API and the UI.

The state of each zone (the serial held, the last success and the last error of each primary, the next refresh, the expiry, and whether a transfer is running) lives in the memory of the service on the leader. After a restart a copy counts as fresh from the time its SOA was written and is refreshed at once. The state shows in the API (section 10.9); `last_error` is one of these stable codes:

| Code | Meaning |
|---|---|
| `dns.transfer.failed` | No answer, a malformed or incomplete answer, or the store refused the result |
| `dns.transfer.tsig` | The answer did not verify, or the key named in `source` is unknown |
| `dns.transfer.refused` | The primary answered REFUSED or NOTAUTH |

These are codes in the transfer status, not HTTP answers of a route.

### 10.7 The read-only rule

The records of a secondary zone come from the primary, so every other write is refused with 409 `dns.zone.secondary` (parameter `zone`): the batch (section 3), the zone file import (section 4) and the actuator of IPAM (section 7). The same code refuses a write to an RRset of origin `transfer` in a primary zone, which are the generated members of a catalog zone (section 10.8); `take_over` does not apply to them. The UI shows the records of a secondary zone with a notice and without edit controls.

### 10.8 Catalog zones

A catalog zone (RFC 9432, schema version 2) is a zone that lists other zones, so that a secondary learns the zones to serve from one transfer instead of one line of configuration each. The setting is `catalog` on the zone, allowed on primary and secondary zones only (400 `dns.zone.invalid` with the field `catalog` otherwise).

- **A secondary catalog zone** (Tenko reads the catalog of another server). After each transfer the members of the catalog become secondary zones of the installation. A member is a PTR record at `<label>.zones.<catalog>`, and the TXT record `version` at the apex must be `"2"`. The new zones take the catalog's primaries and its SOA defaults and carry the description `Member of the catalog zone <name>`. A zone with that description that has left the catalog is deleted with its records.
- **A primary catalog zone** (Tenko writes a catalog for others). Tenko writes the members itself, with the origin `transfer`: one for every primary zone of the same tenant (or without a tenant) whose `transfer.allow` is not empty, catalog zones excepted. The label is the zone's identifier without dashes, and the apex carries the version TXT. When the set of zones changes the catalog gets a serial step and a journal entry, so its secondaries follow by NOTIFY and IXFR. A tenant has at most one primary catalog zone (a second is refused with `dns.zone.invalid` on `catalog`).

The catalog zone transfers like any other zone, so it needs its own `transfer` policy for the secondaries that read it. A member zone transfers only if its own policy allows it: the catalog lists a zone, it does not grant access to it.

### 10.9 Routes and the command line

| Operation | Route | Scope |
|---|---|---|
| `get_dns_zone_transfer` | `GET /dns/zones/{id}/transfer` | `dns.read` |
| `trigger_dns_zone_transfer` | `POST /dns/zones/{id}/transfer` | `dns.write` |

`GET` answers the state of the transfer service for the zone:

```
GET /api/v1/dns/zones/{id}/transfer

200 OK
{"zone": "0190d1c2-...", "serial": 2026101801,
 "primaries": [{"address": "192.0.2.10:53", "last_success": "2026-10-18T10:00:00Z"}],
 "next_refresh": "2026-10-18T11:00:00Z", "expires": "2026-11-01T10:00:00Z", "running": false}
```

A zone the service has not seen (a primary zone, or a controller that does not lead) shows the serial in the store and its primaries without results. `POST` queues a refresh of a secondary zone at once, writes the audit record `dns.transfer.trigger` and answers 202 with the state; a zone of another kind is refused with 409 `dns.zone.invalid`.

```
tenko dns transfer status ad.example.test
tenko dns transfer now ad.example.test
tenko dns zone create example.test --kind primary --ns ns1.example.test --catalog
tenko dns zone update example.test --catalog true
```

`tenko dns transfer status` prints the serial, the timers and a table of the primaries with their last success and last error; `now` queues the refresh and prints the same. `--catalog` on `zone create` and `--catalog true|false` on `zone update` set the catalog flag. The command line creates primary and RPZ zones only; a secondary zone, a transfer policy and the NOTIFY targets are set through the API or the web UI. In the UI the settings tab of a zone has the section "Zone transfers" (the access lists, the NOTIFY targets with their key, `require_tsig`, `xot` and the catalog setting) and, for a secondary zone, the primaries with port, key, XoT and TLS name, the transfer state and the button "Transfer now".

### 10.10 Audit and metrics

| Audit action | When |
|---|---|
| `dns.zone.transfer_out` | A zone was transferred out: the client, the key, the kind (`axfr` or `ixfr`) and the kind requested, the serial, the serial before, the records and the messages. A refusal is recorded as a denied action with its reason, at most once a minute per client |
| `dns.zone.transfer_in` | A transfer in was written (section 10.6) |
| `dns.transfer.trigger` | A transfer was started by hand |

| Metric | Labels | Counts |
|---|---|---|
| `tenko_dns_xfr_total` | `kind`: `axfr_out`, `ixfr_out`, `axfr_in`, `ixfr_in`, `notify_out`, `notify_in`; `outcome`: `ok`, `current`, `refused`, `failed` | Transfers and NOTIFY messages (an IXFR answered in AXFR form counts as `axfr_out`) |
| `tenko_dns_xfr_bytes_total` | `direction`: `out`, `in` | Octets of transfer messages |

### 10.11 The lab

[`deploy/compose/lab-dns`](../deploy/compose/lab-dns/README.md) has a round, `xfr`, that checks all of this against BIND 9 in both directions: TSIG, NOTIFY, IXFR, XoT and catalog zones, the read-only rule and the transfer state of the API. `bench/phase2-dns/scripts/run-m19-xfr.sh` measures M19 (a change of 100 records on a zone of 100,000 records reaches BIND within 5 seconds, and only the change is transferred) on the same lab.

### 10.12 Limits

- The transfer state is in the memory of the leader's service. Another controller does not see it and a restart loses it (the copy is then refreshed at once). Phase 5 or a status row may keep it.
- NOTIFY out waits for the `dns` role of its own process. In Phase 5 a remote `dns` node reports the revision it serves.
- The transfer path reads the journal and writes its audit records through the store of its process, which holds while the role runs in the controller's process (Phase 2).
- A transfer in of more than 20,000 changed RRsets is written in chunks, so it is not one commit and the zone may be served half changed while the write runs. One transfer holds at most 10 million records.
- TSIG is a shared secret per key. GSS-TSIG is not supported (section 10.13).
- Catalog member properties (`group`, `coo`) are not used. Member zones get the catalog's SOA defaults and no transfer policy of their own.
- A zone deleted and created again gets a new catalog label.

### 10.13 The Windows DNS half (owner's checklist)

This is the manual half of the interoperability check with Windows DNS (E15). A domain controller allows the transfer of one Active Directory-integrated zone to the Tenko node and to nothing else, and Tenko holds the zone as a secondary zone. Nothing here is automated. The access is read only (a secondary can read the zone and never change it) and revocable. The names are placeholders: the zone `ad.example.test`, the domain controller `192.0.2.10`, the Tenko node `192.0.2.53`.

**On the domain controller.** Allow the zone transfer to the node's address only.

1. In DNS Manager, open the properties of the zone `ad.example.test` and the tab Zone Transfers. Tick "Allow zone transfers", choose "Only to the following servers" and add `192.0.2.53`. Do not choose "To any server".
2. On the same tab, under Notify, tick "Automatically notify", choose "The following servers" and add `192.0.2.53`.
3. The same in PowerShell on the domain controller:

   ```powershell
   Set-DnsServerPrimaryZone -Name ad.example.test `
     -SecureSecondaries TransferToSecureServers -SecondaryServers 192.0.2.53 `
     -Notify NotifyServers -NotifyServers 192.0.2.53
   ```

4. TCP 53 from the node to the domain controller must be open for the transfer, and UDP 53 from the domain controller to the node for NOTIFY.

**On the Tenko node.** Create the zone as a secondary zone with the domain controller as its primary. In the web UI: DNS, Zones, new zone, kind "secondary", name `ad.example.test`, primary `192.0.2.10`. Or through the API:

```
POST /api/v1/dns/zones
{"name": "ad.example.test", "kind": "secondary",
 "soa": {"mname": "dc1.ad.example.test", "rname": "hostmaster.ad.example.test"},
 "source": {"primaries": [{"address": "192.0.2.10", "port": 53}]}}
```

The SOA and the name servers of the zone come from the domain controller with the first transfer.

**Without a key.** Windows DNS does not sign zone transfers with TSIG (it secures dynamic updates with GSS-TSIG, which Tenko supports from Phase 4, and restricts transfers by address). This zone therefore transfers without a TSIG key, and the access rests on the address restriction on both sides: the domain controller lists only `192.0.2.53`, and Tenko accepts a NOTIFY for the zone only from `192.0.2.10`. `require_tsig` is a setting of zones Tenko serves as primary, not of secondary zones, so it plays no part here. A transfer without a key can be read by anyone who can use the node's address on the path between the two servers, and it carries every record of the zone, including the hosts that registered themselves, so keep that path to the two servers.

**What to check.**

1. `tenko dns transfer status ad.example.test`, or `GET /api/v1/dns/zones/{id}/transfer`: a `serial`, a `last_success` for `192.0.2.10:53` and no `last_error`. A `dns.transfer.refused` means the domain controller refused the node's address (check the Zone Transfers tab); `dns.transfer.failed` means no connection or a malformed answer (check the firewall).
2. Ask the node for a record of the zone: `dig @192.0.2.53 dc1.ad.example.test A`, or `Resolve-DnsName dc1.ad.example.test -Server 192.0.2.53`.
3. Compare the serial of the SOA on both servers: `dig @192.0.2.10 ad.example.test SOA +short` and `dig @192.0.2.53 ad.example.test SOA +short`, or `Resolve-DnsName ad.example.test -Type SOA -Server 192.0.2.10` and the same with `-Server 192.0.2.53`. The serials must be equal.
4. Add a record on the domain controller, for example `Add-DnsServerResourceRecordA -ZoneName ad.example.test -Name xfrtest -IPv4Address 192.0.2.77`. It reaches the node within seconds when the NOTIFY of the domain controller arrives, and within the SOA's `refresh` seconds when it does not (a domain controller with several addresses may send NOTIFY from one that is not `192.0.2.10`, and Tenko ignores it). `tenko dns transfer now ad.example.test` forces the transfer. Remove the test record afterwards.

**To revoke.** On the domain controller remove `192.0.2.53` from the zone's transfer list (the Zone Transfers tab, or `Set-DnsServerPrimaryZone -Name ad.example.test -SecureSecondaries NoTransfer`) and from its notify list (`-Notify NoNotify`). Then delete the secondary zone in Tenko (`DELETE /api/v1/dns/zones/{id}`, or the delete action of the zone in the UI), which removes the copy at once. Without that, the copy keeps answering until the SOA's `expire` seconds have passed and then answers SERVFAIL.
## 11. Views, scopes and weights

A **view** (DNS-20) decides, per query, which version of each zone the query sees and whether the client may recurse. It is a row of `dns.views`: a unique name, match rules, a scope map, a position `order` and an optional recursion access list. One model covers the simple internal and external split, BIND views and Windows zone scopes with Query Resolution Policies (the mapping is below). The service is `tenko_dns::zone::views`, the selection is the view table of the catalog (`tenko_dns::catalog`), and the routes are `/dns/views`.

### The model

| Field | What |
|---|---|
| `name` | 1 to 64 characters without surrounding spaces, unique without case |
| `rules` | The match rules; every rule must hold. No rule: the view matches every query that reaches it |
| `scope_map` | `{zone, scope, weight}` entries: the zone scopes the view sees. A zone not in the map is seen in its `default` scope |
| `order` | The position, from 1; the views are tried in this order |
| `recursion` | The access list of the view's clients that may recurse; absent: the profile's default |
| `description` | Free text, at most 1,000 characters |

A **scope** is one version of a zone's data: every zone has `default`, and more are given when the zone is created or changed through the API (`scopes` of `POST /dns/zones` and `PATCH /dns/zones/{id}`, for example `{"scopes": [{"name": "default"}, {"name": "internal"}, {"name": "external"}]}`; the zone command and the zone settings of the UI do not set scopes yet). A new scope starts with the apex SOA and a copy of the default scope's NS set. Each scope has its own RRsets, SOA serial and journal; a record batch names the scope it changes (`scope`, `default` when absent; `tenko dns record add --scope internal ...`).

### The six tests

A rule is one test with one or more values; any value matches. The rules of a view are and-ed.

| Test | JSON | Matches when | Example |
|---|---|---|---|
| Client subnet | `{"test": "client_subnet", "prefixes": [...]}` | The client address is in one of the prefixes; an IPv4-mapped IPv6 address is its IPv4 address | `["192.0.2.0/24", "2001:db8:10::/48"]` |
| Transport | `{"test": "transport", "transports": [...]}` | The query arrived over one of `udp`, `tcp`, `dot`, `doh` | `["dot", "doh"]` |
| Interface | `{"test": "interface", "addresses": [...]}` | The query arrived on one of the server's addresses | `["192.0.2.53"]` |
| Query type | `{"test": "qtype", "types": [...]}` | The query type is one of these | `["A", "AAAA"]` |
| Query name | `{"test": "qname", "suffixes": [...]}` | The query name is one of these names or below one | `["example.test"]` |
| Time of day | `{"test": "time_of_day", "from_minute": 1320, "to_minute": 360}` | The minute of the day in UTC is in the window, both ends included; a window whose start is after its end runs over midnight | 22:00 to 06:00 |

The client subnet is the source address of the query, not an EDNS Client Subnet option. The interface is the local address the socket received the query on, so a node that listens on two addresses can answer each with a view of its own.

### The order and the first match

The views are tried in `order`; the first whose rules all hold wins, and no other view is consulted for that query. A query no view matches is in the **implicit default view**, which is no row: it sees the `default` scope of every zone and recurses as the profile's default allows. A view without rules, last in order, catches every query the views before it left, and so replaces the implicit default view where its scopes or its recursion list should differ.

Positions are unique and without gaps. A view created at a position, or moved to one by a change of `order`, pushes the views from that position one down; a deleted view closes its gap; a position past the end is the end. The rows whose position moves are written in the same batch as the view, so their revisions move too (a client holding an older `ETag` of another view gets 412 and reads again).

### Scopes and weights

A view's scope map lists, per zone, the scopes the view sees. With one scope of a zone the view sees that scope. With several scopes of one zone, the weights (1 to 1,000) split the view's clients among them: a client gets one scope of the zone, chosen by a hash of its address, in proportion to the weights. The rule, in `tenko_dns::catalog`:

1. The client address as 128 bits (an IPv4 address and an IPv4-mapped IPv6 address are the same 32 bits), its two 64-bit halves xor-ed, then one xorshift-multiply-xorshift round of MurmurHash3's 64-bit finalizer (shift 33, multiplier `0xff51afd7ed558ccd`), cut to its low 32 bits: the client's *pick*.
2. Per zone, the entries in map order with their cumulative weights; the pick modulo the zone's total weight falls into one entry, and that is the scope.

The split is stable: a client sees one answer set, on every node and after every restart, and two clients split as the weights say. It is a split of clients, not of queries: one client is never sent to both scopes of a pair in turn. Measured with a 700/300 pair: 69.3 % of 10,000 IPv6 clients of `2001:db8::/32` and 70.3 % of the 762 IPv4 addresses of the three documentation ranges got the 700 scope (`crates/tenko-dns/tests/views.rs`), and 356 of 500 loopback clients (71.2 %) on the wire (`crates/tenko/tests/acceptance_dns_views.rs`); a 200/500/300 triple gave 19.6, 49.7 and 30.7 %. Several devices behind one NAT address count as one client; an IPv6 client with temporary addresses may change its scope when its address changes.

A scope named by a view must exist in its zone: the view is refused (`dns.view.invalid`, field `scope_map`, parameters `zone` and `scope`) otherwise, and a zone change that removes a scope a view names, or the deletion of a zone a view names, is refused with 409 `dns.view.in_use` (parameter `by`, the views as `view:<name>`). Free the scope by changing or deleting the view first.

### Recursion per view

Who may recurse is decided per view before the cache is read ([dns-resolver.md](dns-resolver.md) section 2.3, TGL-22). A view with `recursion` names an access list ([section 6](#6-access-lists-and-tsig-keys)): the first matching entry decides, and no match refuses with REFUSED and the extended error 18. A view without it, and the implicit default view, follow the profile in force: Home and Standard allow the prefixes IPAM knows and loopback, Hardened nobody, Lab every client. An access list a view names is in use: its deletion is refused (409 `dns.acl.in_use`, `by` lists `view:<name>`), and a list read names the view in `used_by`. `PATCH` with `default_recursion: true` returns a view to the profile's default. The implicit default view has no row and nothing to edit: to widen or narrow its recursion, add a view without rules, last in order, with a list.

The cache is per view: its key carries the view, so an answer a client of one view caused never reaches a client of another, even for the same name (`dns-resolver.md` section 3.1; proven in `views.rs` and on the wire in `acceptance_dns_views.rs`). Forwarding rules can be bound to one view (`view` of a rule); a view a forwarding rule names cannot be deleted (409 `dns.view.in_use`, `by` lists `forwarder:<suffix>`).

### The API and the command line

| Operation | Route | Scope |
|---|---|---|
| `list_dns_views` | `GET /dns/views` | `dns.read` |
| `create_dns_view` | `POST /dns/views` | `dns.write` |
| `get_dns_view` | `GET /dns/views/{id}` | `dns.read` |
| `update_dns_view` | `PATCH /dns/views/{id}` | `dns.write` |
| `delete_dns_view` | `DELETE /dns/views/{id}` | `dns.write` |

The list is in order, paged with a cursor. A read carries the row's revision as the `ETag`; `PATCH` and `DELETE` take `If-Match`. `PATCH` replaces `rules` and `scope_map` when given, moves the view with `order`, sets `recursion` or, with `default_recursion: true`, clears it, and clears `description` with an empty text. Every change is one batch with its audit record (`dns.view.create`, `dns.view.update`, `dns.view.delete`); the role's catalog follows the rows through the store feed, so a change is answered within the feed's delay (milliseconds on one node). Errors: 400 `dns.view.invalid` (parameters `field` and `reason`), 404 `dns.view.not_found`, 409 `dns.view.in_use`, 412 for a stale `If-Match`.

```
tenko dns acl create office --entry 192.0.2.0/24 --entry 2001:db8:10::/48
tenko dns view create office --client-subnet 192.0.2.0/24 --client-subnet 2001:db8:10::/48 \
    --scope example.test:internal --recursion office
tenko dns view create canary --transport dot --transport doh \
    --scope example.test:internal:700 --scope example.test:external:300
tenko dns view create everyone --scope example.test:external
tenko dns view update everyone --order 1
tenko dns view list
tenko dns view update office --default-recursion
tenko dns view delete canary
```

`--client-subnet`, `--transport`, `--interface`, `--qtype` and `--qname` repeat (the values of one flag form one rule), `--time 22:00-06:00` is the window in UTC, `--scope <zone>:<scope>[:<weight>]` repeats (weight 1 when absent), `--order` is the position (last when absent on `create`). On `update`, rule flags replace all rules, `--no-rules` removes them, `--scope` replaces the scope map and `--no-scopes` empties it. A view is named by its name or its identifier. The web UI has the views at `/dns/views`: the list in order with the rules in words and the scopes with their shares, up and down buttons and drag and drop for the order, the dialogs with an editor per test.

### Mapping from Windows and BIND

What the migration adapters of Phase 4 map onto views ([MIGRATION.md](MIGRATION.md), the views and policies note):

| Source | Tenko | Notes |
|---|---|---|
| Windows zone scope (`Add-DnsServerZoneScope`) | A scope of the zone | The scope's records go to the scope; the zone's own records to `default` |
| Windows client subnet (`Add-DnsServerClientSubnet`) | The prefixes of a `client_subnet` rule | A named subnet becomes the values of the rules that name it |
| Query Resolution Policy, criteria `ClientSubnet`, `TransportProtocol`, `ServerInterfaceIP`, `QType`, `TimeOfDay`, `FQDN` with `EQ` | One view with one rule per criterion | `TimeOfDay` is server local time on Windows: converted to UTC at migration (a window across a change of daylight saving time drifts by an hour) |
| QRP `-Condition OR` | One view per criterion, adjacent in order | Tenko and-s the rules of one view |
| QRP `-ZoneScope "a,3;b,1"` (weighted) | `scope_map` with weights 3 and 1 | Windows picks per query, Tenko per client: the share holds, one client sees one scope |
| QRP processing order | `order` | Server-level policies first, then the zone-level ones |
| Zone-level QRP | A view with the policy's criteria and a `qname` rule of the zone's apex | Tenko's order is global: the `qname` rule keeps the view to the zone's names, as the zone-level policy was |
| Recursion scope (`Add-DnsServerRecursionScope`) with its forwarders | The view's `recursion` access list, and forwarding rules bound to the view | `EnableRecursion $false` maps to a list that denies `any` |
| BIND `view` | A view, in the order of `named.conf` | |
| BIND `match-clients` with an `acl` of prefixes | `client_subnet` | Negated elements (`!`) and TSIG keys in `match-clients` go to the loss report |
| BIND `match-destinations` | `interface` | |
| BIND `match-clients { any; }` | A view without rules, last | |
| BIND `allow-recursion` and `recursion no` in a view | The view's `recursion` access list | `recursion no` maps to a list that denies `any` |
| BIND zone in several views with different data | One zone, one scope per view | The data of the first view goes to `default` when that view is the catch-all |

What goes to the loss report: `NE` criteria and negated ACL elements (a view in front with the complement is the manual way), QRP actions `DENY` and `IGNORE` (block lists and response policy are the Tenko tools, [dns-resolver.md](dns-resolver.md) sections 5 and 6), `match-recursive-only`, TSIG keys as view criteria, EDNS Client Subnet criteria, and a zone that exists in only some BIND views (in Tenko every zone exists in every view; its `default` scope can hold only the apex, so other views get NXDOMAIN for its names).

### Limits

| What | Limit |
|---|---|
| Views | 1,000 |
| Rules per view | 32 |
| Values per rule | 1,000 |
| Scope map entries per view | 256 |
| Weight | 1 to 1,000 |
| Name, description | 64, 1,000 characters |

The view table is compiled when the rows change and tried for every query: a view costs one pass over its rules, and a client subnet rule a pass over its prefixes, so a long list of views with long prefix lists slows every query a little; the views table in the catalog is rebuilt as a whole on each change of `dns.views`. The rules have no negation and no regular expressions; time windows are in UTC only.

## 12. The engine

How a query travels from a socket to its answer, how the workers use sockets on each platform, how the index is laid out and kept current, the order of the lookup, EDNS and cookies, TCP, the limits and their settings, the metrics and the allocation rule: for operators who size and tune a node and for builders of the later Phase 2 packages. The decisions behind it are [ADR 0009](adr/0009-dns-wire-format-and-udp-io.md) (wire format and UDP I/O) and [ADR 0017](adr/0017-dns-data-model-and-serving-path.md) (data model and serving path); the contracts are in [dns-contracts.md](dns-contracts.md). The code is `crates/tenko-dns`.

### 12.1 The path of a query

| Step | Where | What |
|---|---|---|
| Receive | `transport::udp`, `transport::tcp` | A UDP worker blocks in `recv_from`; a TCP connection reads a length-prefixed message |
| Parse | `codec` (`DomainCodec` on `domain` 0.12.3) | Header, the one question, OPT with the cookie, TSIG positions; a message that is no query is dropped, one that does not parse gets a header-only FORMERR |
| EDNS and cookies | `respond` | BADVERS for an EDNS version other than 0; the cookie check (section 12.5) |
| Resolve | `authoritative` (the `Resolver`) | View, index, policy, forwarder (section 12.4) |
| Build | `codec` | The answer within the transport's limit, with OPT, the cookie, an extended error and the truncation rules |
| Count | `respond`, `metrics` | Queries by transport, view and RCODE; the latency from arrival to answer; the query log entry |
| Send | the transport | `send_to`, or the TCP write when no pipelined query waits |

Every transport calls the same `Responder`, so UDP and TCP answer alike; a query the resolver forwards is handed to the forwarder's intake (`ForwardSink`; the forwarder of [section 9](#9-the-forwarder), whose recursion check and cache hits run on the query path), which answers the client later through the transport's reply path.

### 12.2 Workers and sockets

| Platform | Layout | Why |
|---|---|---|
| Linux | One blocking thread per worker, each with its own UDP socket bound with `SO_REUSEPORT` to the listen address | The kernel spreads clients over the sockets by flow hash; Spike B measured this layout scaling to 32 workers where a shared socket stopped at 16 |
| Windows | One blocking thread per worker, the workers of an address sharing one UDP socket | Windows has no load-balancing `SO_REUSEPORT`; threads and tokio tasks measured the same, threads idle more cheaply |

Each worker has its own receive buffer (65,535 octets, so a query is never cut), its own query buffers and its own counters; it reads the wall clock once a second, not per query. Workers wake every 200 ms to see a stop. `recvmmsg`, UDP GSO and a BPF steering program are not used (ADR 0009 keeps them as later optimisations).

Because `SO_REUSEPORT` balances by flow hash and not by load, a few clients can leave workers idle: the worker layout (section 12.8) shows the datagrams per worker so that this is visible. `[dns.udp] socket = "shared"` (`--mode shared` of the example server) switches Linux to the shared socket.

Every listen address gets UDP and TCP; an IPv6 address is bound IPv6-only, so `0.0.0.0:53` and `[::]:53` are listened on side by side (DNS-04). The worker count applies per listen address.

### 12.3 The index

The index (`tree::ZoneIndex`) holds one name tree per zone and scope, in two layers:

- **The base** is immutable: every owner name and every empty non-terminal is stored once in one arena of wire names, the RRsets as runs of the stored record data (the uncompressed wire form of the rows, which the codec copies into the answer), the nodes and RRsets in flat vectors, and an open-addressing table of 4-octet slots maps a name to its node. A lookup hashes the name once and compares it with the arena.
- **The overlay** holds the nodes changed since the base was built, or tombstones for removed ones. A lookup reads it first when it is not empty. When it holds more than an eighth of the base (and more than 1,024 nodes), the writer folds it into a new base.

The index is immutable as a whole: a delta produces a new index that shares every base and every zone it does not touch and copies only the overlays it changes. The catalog (`catalog::Catalog`: the index, the view table and the forwarding table) sits behind one pointer swap (`arc-swap`, as ADR 0002's index swap): a worker loads the current catalog for each query without a lock, and the one writer (`catalog::follow`) applies the feed's deltas in revision order on tokio's blocking pool and stores each new catalog. A reset of the feed (a snapshot install) builds a new catalog and swaps it whole, so answers never stop (M1). A delta that does not follow the revision held makes the writer ask the feed for a new image.

RRsets of a zone the index does not hold (they arrived before their zone, or their zone left) are kept aside and join the zone when it arrives. `ZoneIndex::stats` reports the zones, scopes, nodes, RRsets, records and name octets of the bases, the overlay nodes and the RRsets kept aside (for M18 and the health view).

The reference implementation `MemIndex` is the test oracle: the tests build both from the same rows and compare every lookup over a generated zone of 100,000 names and after every delta of a random sequence, and a hand-written corpus pins the special cases.

### 12.4 The lookup

The order of one query (plan sections 2.2 and 2.3):

1. **Header.** An opcode other than QUERY is NOTIMP. A signed query is NOTAUTH (the resolver verifies no TSIG; a signed SOA query of a secondary is answered by the transfer path before the resolver, section 10.3). A class other than IN is REFUSED. The meta types OPT, TKEY and TSIG are FORMERR; AXFR and IXFR go to the transfer path of section 10.3 first, and a resolver reached without it answers them REFUSED with the extended error "Prohibited"; MAILA and MAILB are NOTIMP.
2. **Rate limiter**: the query is admitted or dropped (`RateLimiter::admit_query`; WP5.2 implements RRL).
3. **View** (DNS-20): the first view in `order` whose rules all match (client subnet, transport, local address, query type, time of day, query name) wins; none matching is the implicit default view, which sees the default scope of every zone. A view's weights pick one scope per zone, with a value derived from the client address so that one client keeps seeing the same scope.
4. **Zone**: the served zone (primary or secondary) with the longest apex at or above the name. A stub, forward or RPZ zone is not answered from.
5. **Name**: the exact name first; else its closest encloser. On the way from the apex down, a zone cut (NS below the apex) refers, except for a DS query at the cut itself, which the parent answers; a DNAME above the name redirects it. A name that does not exist is answered from the wildcard at its closest encloser (RFC 4592), with the question name as the owner.
6. **Chains**: a CNAME is followed inside the index and a DNAME's CNAME is synthesized (owner the current name, TTL the DNAME's, RFC 6672), up to eight steps in all; a loop or a longer chain stops with what was found. A synthesized name over 255 octets is YXDOMAIN.
7. **Sections** (minimal responses): a positive answer carries no NS in the authority section; the additional section carries the A and AAAA RRsets of the targets of MX, SRV and NS answers that the index holds, each target once. A referral carries the NS RRset (and the DS for a client with the DO bit), then the in-domain glue, which must fit (else the answer is truncated, RFC 9471), then the other glue inside the parent zone, which is left out when it does not fit. NODATA and NXDOMAIN carry the zone's SOA with the TTL of RFC 2308: the smaller of the SOA's TTL and its MINIMUM. NXDOMAIN at the end of a chain is the RCODE of the last name (RFC 6604). A query for ANY gets one RRset of the name (RFC 8482).
8. **Bits**: AA for an answer from a zone, clear for a referral; RA when a forwarder is configured; AD never (no validation).
9. **Outside the zones**: the policy (`PolicyEngine`: RPZ and block lists, WP5.2) may block with NXDOMAIN, NODATA or a redirect address, with the extended error "Blocked"; else, when the client asked for recursion, the forwarding rule with the longest suffix (a rule of the query's view before one of all views), or the default forwarder of the configuration, gets the query; else REFUSED with the extended error "Not Authoritative".
10. **Rate limiter** on the response (`admit_response` by response kind and zone): send it, slip it (an empty answer with TC, so a real client retries over TCP) or drop it.

### 12.5 EDNS and cookies

- **EDNS** (RFC 6891): the server's UDP size is 1,232 octets (DNS flag day 2020; the setting `edns.udp_size`, 512 to 4,096). A UDP answer is at most the requester's size clamped to 512 and the server's size, 512 octets without EDNS; TCP answers go up to 65,535. The OPT record of the answer advertises the server's size, echoes the DO bit, carries the extended RCODE (BADVERS 16, BADCOOKIE 23), the cookie and an extended error (RFC 8914: "Blocked" 15, "Prohibited" 18, "Not Authoritative" 20, "Not Supported" 21). Unknown options are ignored; a second OPT record, an OPT not owned by the root or a malformed option is FORMERR.
- **Truncation**: when an answer or authority record does not fit, the answer is the header, the question and OPT with TC set; additional records that do not fit are left out without TC, except required glue.
- **Cookies** (RFC 7873) in the interoperable server-cookie form of RFC 9018: version 1, a 32-bit timestamp and a SipHash-2-4 of the client cookie, those fields and the client address under a 16-octet secret. The secret is the node's (`CookieSecret`, owned by the server): random at start and replaced every 24 hours, the previous one staying valid, so a cookie is accepted for its lifetime of one hour (and up to five minutes ahead of the clock) across a rotation. Every query with a client cookie gets the client cookie and a fresh server cookie back; a malformed cookie is FORMERR.
- **Cookie modes** (`cookies`): `on` (the default) answers a missing or invalid server cookie normally with a fresh one; `required` answers a UDP query whose client sent a cookie without a valid server cookie with BADCOOKIE and a fresh cookie, so that a spoofed source gets no amplified answer; queries without any cookie and every TCP query are answered normally; `off` ignores cookies.

### 12.6 TCP

DNS over TCP follows RFC 7766 on the tokio runtime: each message is preceded by its two-octet length; a client may pipeline queries, which are answered in arrival order, and the answers are written together when no further query is buffered (or 32 KiB of answers wait). A connection is closed after the idle time without a query (10 seconds), when a message is cut, or when the server stops. The node accepts at most 1,000 open connections and 10 from one client address; a connection over either cap is closed at once and counted. TCP never answers BADCOOKIE. The query buffers are kept per runtime thread, so a TCP query allocates nothing either.

### 12.7 Settings and limits

The `[dns]` keys of the configuration (`deploy/tenko.example.toml`, [section 8](#8-the-dns-role)) and the fields of `server::ServerConfig` they set. The four keys WP4.1 proposed (`udp.socket`, `udp.recv_buffer`, `udp.send_buffer`, `cookies`) are keys with the engine's defaults:

| Key | Field | Default | Meaning |
|---|---|---|---|
| `listen` | `listen` | `0.0.0.0:53`, `[::]:53` | Addresses for UDP and TCP; port 53 needs `CAP_NET_BIND_SERVICE` on Linux |
| `workers` | `udp.workers` | 0: the CPU count | UDP workers per listen address, up to 256 |
| `udp.socket` | `udp.mode` | `auto`: `reuseport` on Linux, `shared` elsewhere | Socket per worker or one shared socket; `reuseport` is refused outside Linux |
| `udp.recv_buffer`, `udp.send_buffer` | `udp.recv_buffer`, `udp.send_buffer` | 8 MiB | `SO_RCVBUF` and `SO_SNDBUF`, 0 keeps the system's; the system caps them (`net.core.rmem_max`) |
| `tcp.max_connections` | `tcp.max_connections` | 1000 | Open TCP connections per node, 1 to 100,000 |
| `tcp.per_client` | `tcp.per_client` | 10 | Open TCP connections per client address, 1 to 1,000 |
| `tcp.idle_secs` | `tcp.idle` | 10 | Seconds without a query before a TCP connection is closed, 1 to 300 |
| `edns.udp_size` | `edns_udp_size` | 1232 | The server's EDNS UDP size, 512 to 4096 |
| `cookies` | `cookies` | `on` | `on`, `required` or `off` (section 12.5) |

The forwarder's keys (`forwarders`, `forward_timeout_ms`, `forward_retries`, `upstream_ca`, `[dns.cache]`) are in [dns-resolver.md](dns-resolver.md) section 4.5, the query log's (`[dns.log]`) in [section 8](#8-the-dns-role).

The fixed limits: a CNAME and DNAME chain of eight steps; 8,192 records and 192 KiB of names and data per answer before the build (an answer over that is truncated); messages up to 65,535 octets. The metrics switch of M22 is not a configuration key: metrics are always on in a node, and only the example server can switch them off to measure their cost.

### 12.8 Metrics and the worker layout

The engine counts `tenko_dns_queries_total{proto,view,rcode}` and observes `tenko_dns_query_duration_seconds{proto}` (50 µs to 2 s, from the arrival of a query to its answer) on the calling thread's shard of the registry (OPS-21); `metrics::register` seals and registers both at the role's start. `view` is `default` for the implicit default view and `named` for any configured view (per-view series come with view management, WP6.4); `rcode` is one of `noerror`, `formerr`, `servfail`, `nxdomain`, `notimp`, `refused`, `notauth`, `badvers`, `badcookie` or `other`. Dropped queries are not counted there; a forwarded query is counted when the forwarder answers it, with the RCODE it relayed (SERVFAIL when every upstream failed), and its latency runs from the hand-over to the answer ([section 9](#9-the-forwarder)); a cache hit is counted as any answer of the query path.

`Server::layout` reports the socket mode, the workers per address and, per UDP worker, its address, its socket and its counters (received, sent, dropped, forwarded, receive and send errors), and the TCP listeners with the open connections and the refused ones. `GET /api/v1/nodes/{id}/dns` shows it (`socket_mode`, `udp_workers`, `tcp_open`, `tcp_refused`; [section 8](#8-the-dns-role)); uneven `received` counts across `reuseport` workers are the flow-hash effect of section 12.2.

### 12.9 No allocation per query

The query path allocates nothing once its buffers exist (ADR 0009): the request lives in fixed-size fields, the answer in an arena reserved per worker, the output reuses its vector, names synthesized from a DNAME live in fixed buffers, the catalog is read through the swap, and metrics are relaxed atomic adds. `crates/tenko-dns/tests/alloc.rs` enforces it with a counting global allocator: after proving that it sees a deliberate allocation, it runs parse and build, truncation and FORMERR, index lookups, and the whole path of thirteen kinds of query through the responder, the authoritative resolver, the production index and the codec, with metrics and cookies on, and fails on a single allocation. Only a query handed to the forwarder is copied, off the query path. A change that allocates per query fails this test.

### 12.10 Measurements

M16 (QPS per core on loopback, UDP and TCP) was first measured on `crates/tenko-dns/examples/authoritative.rs`, which serves the `zonegen` zone of `bench/phase2-dns` through this engine (`bench/phase2-dns/results/2026-10-17-m16-loopback.md`), against the Spike B baseline of the same harness. In short (loopback, upper bounds, 8 client sockets with 32 queries in flight each):

| Platform | UDP, 1 / 4 / 8 workers | QPS per server core, UDP | TCP, 1 / 4 / 8 runtime threads |
|---|---|---|---|
| Windows 11 (shared socket) | 124k / 448k / 698k | 125k / 113k / 88k | 430k / 550k / 543k |
| WSL2, musl (`SO_REUSEPORT`) | 130k / 744k / 1.11M | 130k / 187k / 222k | 464k / 1.67M / 2.05M |
| WSL2, musl (shared socket) | – / 740k / 1.78M | – / 185k / 223k | |

At 4 and 8 workers the engine costs the same CPU per query as the Spike B responder; at one worker it costs 1 to 1.7 µs more. With few client sockets `SO_REUSEPORT` leaves workers idle (section 12.2).

M16 again on `tenko serve --roles controller,dns` (the role of section 8, the zone imported through the CLI into the store; `bench/phase2-dns/results/2026-10-17-m16-serve.md`) gives the same CPU per query as the example on Windows (7.54, 8.88 and 11.36 µs at 1, 4 and 8 workers) and within 0.4 µs of it in WSL2: the controller around the role adds nothing measurable to the query path. UDP per server core: 133k / 113k / 88k on Windows, 123k / 179k / 256k in WSL2 with musl; TCP up to 575k on Windows and 2.17M in WSL2.

M18 (`2026-10-17-m18-zone-load.md`): the index holds 926 MiB for 7.2 M RRsets (135 octets per RRset, counted by `tests/index_memory.rs`), under the 1.5 GiB threshold; the role builds it from the store in 35 s (Windows) and 51 s (musl) at start. A zone file import of that size takes 125 s and 443 s without the role, and the role adds 49 and 85 percent to it (section 12.11).

### 12.11 Known limits

- The UDP sockets do not read the destination address of a query (no `IP_PKTINFO`). On a host with more than one address, a socket bound to the wildcard address may answer from another source address than the client asked, which the client discards; such a node lists each of its addresses in `listen`. The role does not expand a wildcard into the host's addresses (the process has no interface list to read them from without a new dependency); it logs this limit at start when `listen` holds a wildcard address. For the same reason an interface rule of a view compares the address a socket is bound to.
- When Tenko serves both a parent zone and its child, a DS query at the child's apex is answered from the child zone (the longest apex wins), where RFC 4035 (section 3.1.4.1) asks for the parent's DS; DNSSEC (WP6.3) handles this case.
- A delta copies the overlay of each scope it touches, and folding an overlay into a new base is linear in the scope's size; very large zones with a high rate of dynamic updates (M21) may need an incremental base later. The same work slows a large zone file import into a serving node: at 7.2 M RRsets the import takes 49 percent longer on Windows and 85 percent longer with the musl allocator than without the role (M18). An incremental base, or a bulk path that builds a zone's base once when an import replaces it, would remove that.
- The role builds its index from one image of all its rows: at start the image and the index are both in memory (3.7 GiB and 0.9 GiB at 7.2 M RRsets), and the allocator keeps part of the image after it is freed (the node's RSS after a start with 7.2 M RRsets is 1.7 GiB above an empty node on Windows, 2.3 GiB with musl). Building the index from the store's rows in pages would lower that peak.
- `SO_REUSEPORT` spreads by flow hash: a load generator with few sockets reaches only some workers (section 12.2).
