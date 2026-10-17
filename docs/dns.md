# DNS: zones, records, zone files, serials, access lists and TSIG keys

This page describes how Tenko DDI holds DNS data: zones and their kinds, RRsets and the rules they keep, batch changes with a dry run, zone file import and export, SOA serials and the journal that zone transfers read, access lists and TSIG keys. It is for an operator who manages zones through the API, the command line or the web UI, and for a developer who builds on the zone service. It describes the zone service `tenko_dns::zone`, the model `tenko_core::dns` and the `/dns` routes of `tenko-api`; where this page and the code differ, the code is right. The requirements are DNS-01, DNS-07, DNS-09, DNS-11, DNS-24 and MIG-15 in [REQUIREMENTS.md](REQUIREMENTS.md); the decisions are in [ADR 0017](adr/0017-dns-data-model-and-serving-path.md) and section 2 of the [Phase 2 plan](plans/phase-2-plan.md). The contracts every Phase 2 package shares (tables, routes, codes, audit actions) are listed in [dns-contracts.md](dns-contracts.md). Views, forwarders, block lists, transfers, dynamic updates and DNSSEC get their sections when their packages land.

Terms used below: an **RRset** is the records of one owner name and type in one scope of a zone. A **scope** is one version of a zone's data that views choose (DNS-20); every zone has the scope `default`. The **apex** is the zone's own name. An RRset's **origin** says who owns it: `manual` (API, UI, zone file), `ipam` (the DNS actuator of IPAM), `dynamic` (RFC 2136), `dhcp` and `ad`.

Contents:

1. [Zones and kinds](#1-zones-and-kinds)
2. [Records and the RRset rules](#2-records-and-the-rrset-rules)
3. [Batch changes and the dry run](#3-batch-changes-and-the-dry-run)
4. [Zone files: import, export, limits](#4-zone-files-import-export-limits)
5. [Serials and the journal](#5-serials-and-the-journal)
6. [Access lists and TSIG keys](#6-access-lists-and-tsig-keys)

All routes are under `/api/v1` and exist only while the DNS module runs (OPS-25); otherwise they answer 404 `sys.route_not_found`. Reads need the scope `dns.read`, changes `dns.write`, everything on keys `dns.keys` (section 6). Every change is committed with its audit record in one write, and every change of the DNS data appears on the event topic `dns`.

## 1. Zones and kinds

| Kind | Holds data in Tenko | Phase 2 |
|---|---|---|
| `primary` | yes | Tenko is the source of the zone |
| `rpz` | yes | a response policy zone (the policy engine is WP5.2) |
| `secondary` | no | the row only; transfers in are WP6.1 |
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
| `dns.zone.invalid` | 400 | A zone without data (secondary, stub, forward), a scope the zone lacks |

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

An access list has a unique name (1 to 64 characters, compared without case), at most 1,000 entries and a description. An entry is a prefix (`{"kind": "prefix", "prefix": "192.0.2.0/24"}`), a TSIG key (`{"kind": "key", "name": "transfer.example.test"}`) or `any`, each optionally `"deny": true`; the first entry that matches decides, and no match refuses. Zones name lists in their transfer policy (`transfer.allow`) and update policy (`update.allowed`); a list a zone names cannot be deleted (409 `dns.acl.in_use`, parameter `by`). A list read carries `used_by` (`zone:<name>`) and its revision as the `ETag`.

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
