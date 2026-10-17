# DNS contracts

This page lists the contracts of the DNS module that every Phase 2 package builds on (WP4.0 of [phase-2-plan.md](plans/phase-2-plan.md), section 3): the store tables, the API routes with their scopes, the event topic, the error codes, the audit actions, the metric families, the node-sync declaration and the engine traits. It is for the builders of WP4.1 to WP6.5 and for reviewers who check that a package keeps to them. The decisions behind them are in [ADR 0017](adr/0017-dns-data-model-and-serving-path.md). It is temporary: WP4.2 folds it into `docs/dns.md`. Where this page and the code differ, the code is right: `tenko_core::dns` (model, tables, codes, actions, scopes), `tenko_dns` (engine contracts, metrics), `tenko-api` `routes::dns` (routes), `tenko_cluster::node_sync` (node subset, secret purposes).

Contents:

1. [Store tables](#1-store-tables)
2. [Model](#2-model)
3. [API routes and scopes](#3-api-routes-and-scopes)
4. [Event topic](#4-event-topic)
5. [Error codes](#5-error-codes)
6. [Audit actions](#6-audit-actions)
7. [Metric families](#7-metric-families)
8. [Node sync](#8-node-sync)
9. [Engine contracts](#9-engine-contracts)
10. [Data format](#10-data-format)

## 1. Store tables

All in the namespace `dns` of the replicated store; the constants are `tenko_core::dns::tables`.

| Table | Key | Value | Written by | Node role `dns` |
|---|---|---|---|---|
| `dns.zones` | `ZoneId` | `Zone` | the zone service (WP4.2), the reverse-zone planner (WP4.4) | yes |
| `dns.rrsets` | zone, scope, owner name, type (`RrSetKey`) | `RrSet` | the zone service, the actuator, dynamic updates, transfers in | yes |
| `dns.views` | `ViewId` | `View` | WP6.4 | yes |
| `dns.forwarders` | `ForwardRuleId` | `ForwardRule` | WP5.1 | yes |
| `dns.acls` | `AclId` | `Acl` | WP4.2 | yes |
| `dns.keys.meta` | key name (`KeyName`) | `KeyMeta` (the secret is a vault secret, purpose `tsig`) | WP4.2 | yes |
| `dns.lists` | `BlockListId` | `BlockList` | WP5.2 | yes |
| `dns.list_versions` | (`BlockListId`, version) | `ListVersion` | the list service (WP5.2) | yes |
| `dns.journal` | (`ZoneId`, `ScopeName`, `Revision`) | `JournalEntry` | the zone service, bounded by entries and days | yes |
| `dns.sign_state` | `ZoneId` | `SignState` with `DnssecKeyMeta` (private keys are vault secrets, purpose `dnssec`) | the signing service (WP6.3) | no (controllers only) |

Keys of owner names sort by labels from the root down with the octet 0x01 between labels, so a name and everything below it are one key range (`DnsName::subtree_prefix`).

## 2. Model

`tenko_core::dns`, with serde and `ToSchema`:

| Type | What |
|---|---|
| `DnsName` | Canonical lowercase name without the trailing dot, `.` for the root; labels of `a-z`, `0-9`, `-`, `_`, `/` (RFC 2317) and a leftmost `*` |
| `ScopeName`, `Rtype` | A zone scope (`default` always exists); a record type, printed as its mnemonic or `TYPEnnn` |
| `Rdata`, `RecordData` | The stored uncompressed wire form of a record's data; its typed view of A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, TLSA, SVCB, HTTPS and RFC 3597 data for every other type |
| `RrSet`, `RrSetKey` | The records of one owner and type in one scope, with `origin` (`manual`, `ipam`, `dynamic`, `dhcp`, `ad`) and the TSIG key of a dynamic update |
| `Zone` | Name, `ZoneKind` (primary, secondary, stub, forward, rpz), tenant, scopes, `SerialPolicy`, `SoaDefaults`, `TransferPolicy`, `UpdatePolicy`, `DnssecPolicy`, `SecondarySource`, `reverse_of` |
| `View`, `MatchRule`, `ScopeWeight` | Views with the six tests of DNS-20 and the weighted scopes per zone |
| `ForwardRule`, `Upstream` | Forwarding by longest suffix, plain, DoT or DoH |
| `Acl`, `AclEntry` | Access lists of prefixes, keys and `any`, first match decides |
| `KeyMeta`, `DnssecKeyMeta`, `SignState` | TSIG key metadata; DNSSEC keys and the signing state |
| `BlockList`, `ListVersion` | Block lists and their compiled versions |
| `JournalEntry` | One serial step of a zone scope, for IXFR |

The rules (`RrSet::check`, `check_node`, `check_apex`, `Zone::validate` and the `validate` of views, rules and lists): the owner is in the zone; no meta type; TTL at most 2^31 - 1; 1 to 4,096 records without duplicates, each valid for its type; one record in a CNAME, DNAME or SOA set; SOA at the apex only, CNAME never there, DS never at the apex; a wildcard owns no NS, SOA or DS; a CNAME stands alone beside RRSIG and NSEC; beside a delegation only DS, RRSIG, NSEC and glue addresses; the apex holds SOA and NS. TXT strings over 255 octets are split on input at character boundaries (DNS-24).

## 3. API routes and scopes

Under `/api/v1`, tag `dns`, registered only while the DNS module runs (OPS-25; otherwise 404 `sys.route_not_found`). Until its package builds it, every operation checks the caller's scope and answers 501 `sys.not_implemented`. Request and answer types are declared in the OpenAPI document.

| Scope | Grants | Held by |
|---|---|---|
| `dns.read` | Read on zones, records, views, forwarders, access lists, block lists | viewer, operator, admin |
| `dns.write` | Create, update, delete and execute on the same kinds | operator, admin |
| `dns.keys` | Every action on TSIG and DNSSEC keys (changes need an interactive session) | admin |

The object kinds of authorization and audit are `zone` (records authorize as their zone), `dns_view`, `dns_forwarder`, `dns_acl`, `dns_key`, `dns_list`; they are global-only for grants in Phase 2.

| Operation | Operation id | Scope | Purpose |
|---|---|---|---|
| `GET /api/v1/dns/zones` | `list_dns_zones` | `dns.read` | List DNS zones |
| `POST /api/v1/dns/zones` | `create_dns_zone` | `dns.write` | Create a DNS zone |
| `GET /api/v1/dns/zones/{id}` | `get_dns_zone` | `dns.read` | Get a DNS zone |
| `PATCH /api/v1/dns/zones/{id}` | `update_dns_zone` | `dns.write` | Change a DNS zone |
| `DELETE /api/v1/dns/zones/{id}` | `delete_dns_zone` | `dns.write` | Delete a DNS zone and its records |
| `GET /api/v1/dns/zones/{id}/records` | `list_dns_records` | `dns.read` | List the RRsets of a zone |
| `POST /api/v1/dns/zones/{id}/records/batch` | `change_dns_records` | `dns.write` | Change RRsets of a zone in one batch |
| `POST /api/v1/dns/zones/{id}/records/import` | `import_dns_zone_file` | `dns.write` | Import a zone file into a zone |
| `GET /api/v1/dns/zones/{id}/records/export` | `export_dns_zone_file` | `dns.read` | Export a zone as a zone file |
| `GET /api/v1/dns/zones/{id}/dnssec` | `get_dns_zone_dnssec` | `dns.read` | Get the signing state and keys of a zone |
| `POST /api/v1/dns/zones/{id}/dnssec/rollover` | `start_dns_key_rollover` | `dns.keys` | Start a DNSSEC key rollover |
| `GET /api/v1/dns/zones/{id}/transfer` | `get_dns_zone_transfer` | `dns.read` | Get the transfer state of a zone |
| `POST /api/v1/dns/zones/{id}/transfer` | `trigger_dns_zone_transfer` | `dns.write` | Transfer a secondary zone now |
| `GET /api/v1/dns/views` | `list_dns_views` | `dns.read` | List DNS views |
| `POST /api/v1/dns/views` | `create_dns_view` | `dns.write` | Create a DNS view |
| `GET /api/v1/dns/views/{id}` | `get_dns_view` | `dns.read` | Get a DNS view |
| `PATCH /api/v1/dns/views/{id}` | `update_dns_view` | `dns.write` | Change a DNS view |
| `DELETE /api/v1/dns/views/{id}` | `delete_dns_view` | `dns.write` | Delete a DNS view |
| `GET /api/v1/dns/forwarders` | `list_dns_forwarders` | `dns.read` | List forwarding rules |
| `POST /api/v1/dns/forwarders` | `create_dns_forwarder` | `dns.write` | Create a forwarding rule |
| `GET /api/v1/dns/forwarders/{id}` | `get_dns_forwarder` | `dns.read` | Get a forwarding rule |
| `PATCH /api/v1/dns/forwarders/{id}` | `update_dns_forwarder` | `dns.write` | Change a forwarding rule |
| `DELETE /api/v1/dns/forwarders/{id}` | `delete_dns_forwarder` | `dns.write` | Delete a forwarding rule |
| `GET /api/v1/dns/acls` | `list_dns_acls` | `dns.read` | List DNS access lists |
| `POST /api/v1/dns/acls` | `create_dns_acl` | `dns.write` | Create a DNS access list |
| `GET /api/v1/dns/acls/{id}` | `get_dns_acl` | `dns.read` | Get a DNS access list |
| `PATCH /api/v1/dns/acls/{id}` | `update_dns_acl` | `dns.write` | Change a DNS access list |
| `DELETE /api/v1/dns/acls/{id}` | `delete_dns_acl` | `dns.write` | Delete a DNS access list |
| `GET /api/v1/dns/keys` | `list_dns_keys` | `dns.keys` | List TSIG keys |
| `POST /api/v1/dns/keys` | `create_dns_key` | `dns.keys` | Generate or import a TSIG key |
| `GET /api/v1/dns/keys/{key}` | `get_dns_key` | `dns.keys` | Get a TSIG key |
| `DELETE /api/v1/dns/keys/{key}` | `delete_dns_key` | `dns.keys` | Delete a TSIG key |
| `GET /api/v1/dns/lists` | `list_dns_lists` | `dns.read` | List block lists |
| `POST /api/v1/dns/lists` | `create_dns_list` | `dns.write` | Create a block list |
| `GET /api/v1/dns/lists/{id}` | `get_dns_list` | `dns.read` | Get a block list |
| `PATCH /api/v1/dns/lists/{id}` | `update_dns_list` | `dns.write` | Change a block list |
| `DELETE /api/v1/dns/lists/{id}` | `delete_dns_list` | `dns.write` | Delete a block list |
| `POST /api/v1/dns/lists/{id}/fetch` | `fetch_dns_list` | `dns.write` | Fetch and compile a block list now |
| `GET /api/v1/nodes/{id}/dns` | `get_node_dns_status` | `dns.read` | Get the DNS role of a node |
| `POST /api/v1/nodes/{id}/dns/cache/flush` | `flush_node_dns_cache` | `dns.write` | Flush a node's DNS cache |
| `GET /api/v1/nodes/{id}/dns/log` | `read_node_dns_log` | `dns.read` | Read a node's DNS query log |

The node routes sit beside the node's other routes, as the scan configuration of the Discovery module does, and also need the action on the node.

## 4. Event topic

`dns` (`GET /events?topics=dns`): events of every `dns.*` table, references only; a change of `dns.zones` names the zone. The `kind` values of the events the DNS services publish are `dns.zone.changed`, `dns.zone.serial`, `dns.transfer` and `dns.signing` (`tenko_core::dns::events`). A principal reads the topic with `dns.read`.

## 5. Error codes

`tenko_core::dns::codes`, stable once merged:

| Code | Status | When |
|---|---|---|
| `dns.zone.not_found` | 404 | No such zone |
| `dns.zone.exists` | 409 | A zone of this name exists |
| `dns.zone.invalid` | 400 | The zone settings break a rule (`field`, `reason`) |
| `dns.record.invalid` | 400 | A record or RRset breaks a rule of its type (`name`, `type`, `reason`) |
| `dns.record.conflict` | 409 | RRsets of one owner conflict (`name`, `type`, `reason`) |
| `dns.record.origin` | 409 | The writer may not replace an RRset of another origin |
| `dns.zonefile.invalid` | 422 | A zone file does not parse (`line`, `reason`) |
| `dns.view.not_found`, `dns.view.invalid` | 404, 400 | Views |
| `dns.forwarder.not_found`, `dns.forwarder.invalid` | 404, 400 | Forwarding rules |
| `dns.acl.not_found`, `dns.acl.in_use` | 404, 409 | Access lists |
| `dns.key.not_found`, `dns.key.exists` | 404, 409 | TSIG keys |
| `dns.list.not_found`, `dns.list.invalid` | 404, 400 | Block lists |
| `dns.update.refused` | 403 | A dynamic update was refused (key, ACL, prerequisite) |
| `dns.transfer.refused` | 403 | A zone transfer was refused (ACL, key) |
| `dns.node.not_dns` | 409 | The node does not run the `dns` role |
| `dns.module.disabled` | 409 | The DNS module is switched off (for the role and the services; the routes answer 404) |

## 6. Audit actions

`tenko_core::dns::audit`, one record in the batch of each change:

| Action | What |
|---|---|
| `dns.zone.create`, `dns.zone.update`, `dns.zone.delete`, `dns.zone.export` | Zones; a zone file export (MIG-15) |
| `dns.record.change`, `dns.record.import`, `dns.record.actuate` | RRsets changed by the API or UI, imported from a zone file, changed by the actuator of IPAM |
| `dns.key.create`, `dns.key.delete`, `dns.key.rollover` | TSIG keys; DNSSEC rollovers |
| `dns.update.apply`, `dns.update.refuse` | Dynamic updates (RFC 2136) |
| `dns.view.create`, `dns.view.update`, `dns.view.delete` | Views |
| `dns.forwarder.create`, `dns.forwarder.update`, `dns.forwarder.delete` | Forwarding rules |
| `dns.acl.create`, `dns.acl.update`, `dns.acl.delete` | Access lists |
| `dns.list.create`, `dns.list.update`, `dns.list.delete`, `dns.list.compile` | Block lists and their compiled versions |
| `dns.transfer.trigger`, `dns.cache.flush` | A transfer started by hand; a node's cache flushed |

The system component of the DNS services' own writes is `dns`.

## 7. Metric families

`tenko_dns::metrics` (counters get `_total` from the encoder, docs/observability.md):

| Family | Type | Labels |
|---|---|---|
| `tenko_dns_queries` | counter | `proto`, `view`, `rcode` |
| `tenko_dns_query_duration_seconds` | histogram (50 µs to 2 s) | `proto` |
| `tenko_dns_cache_hits`, `tenko_dns_cache_misses`, `tenko_dns_cache_stale` | counter | |
| `tenko_dns_upstream_queries` | counter | `upstream`, `outcome` |
| `tenko_dns_upstream_duration_seconds` | histogram | `upstream` |
| `tenko_dns_rrl_dropped` | counter | |
| `tenko_dns_blocked` | counter | `list` |
| `tenko_dns_zone_serial` | gauge | `zone` |
| `tenko_dns_signing_runs` | counter | `outcome` |
| `tenko_dns_signing_duration_seconds` | histogram (1 ms to 5 min) | |
| `tenko_dns_log_dropped` | counter | |

## 8. Node sync

Declared for Phase 5 and consumed by no node in Phase 2 (plan section 2.10): `Subset::new(node, &[Role::Dns]).role_tables()` lists every `dns.*` table except `dns.sign_state`, and `purpose_allowed("tsig" | "dnssec", &[Role::Dns])` holds (`tenko_cluster::node_sync`). The configuration stream of `Config.Watch` does not carry the role tables yet. The node commands `dns.cache.flush`, `dns.log.read`, `dns.stats` and the report `dns.status` are WP4.3's, behind the node-command interface; `Dns.Update` is Phase 5.

## 9. Engine contracts

`tenko_dns`:

| Trait | Contract | Reference implementation |
|---|---|---|
| `Codec` | Parse the header, the question, OPT (cookie) and TSIG (positions for the MAC) into a `Request`; build an `AnswerBuf` with EDNS, the extended RCODE, cookies, extended errors and the truncation rules; allocation-free | `DomainCodec` on `domain` 0.12.3; a `hickory-proto` codec in the differential test |
| `ZoneFeed` | An image (`DnsData`) at a revision, then deltas in revision order or a reset; never a store handle | `MemFeed` |
| `Index` | Lookup by lowercase wire name and type: answer, CNAME, DNAME, delegation with DS, NODATA, NXDOMAIN with the closest encloser and the SOA, wildcard synthesis, scopes per view, glue, NSEC covering, CNAME chains followed inside the index (`resolve`, at most 8) | `MemIndex` |
| `Resolver` | The one lookup path of every transport; answers or hands the query to the forwarder | (WP4.1, WP4.3, WP5.1) |
| `Upstream` | One exchange with one upstream, plain, DoT or DoH | (WP4.3, WP5.1) |
| `PolicyEngine` | RPZ and block list verdicts with the extended error | `NoPolicy` |
| `RateLimiter` | RRL and per-client limits | `Unlimited` |
| `QueryLogSink` | The non-blocking query log, counting drops | `NullLog` |

The tests that hold the contracts: `crates/tenko-dns/tests/alloc.rs` (no allocation in parse, build and lookup, after proving the counter sees one), `tests/differential.rs` (the same requests and octets from both codecs over 18 answers), `tests/index.rs` (the reference index and feed), `crates/tenko-core/tests/dns_model.rs` (properties of the model) and the fuzz target `dns_codec`.

## 10. Data format

The format of the data directory is 3 from WP4.0 on (an empty migration, docs/upgrades.md section 4): a format 2 binary cannot decode the `dns` namespace, the DNS object kinds or the system component `dns`. The tables later Phase 2 packages add in the namespace need no format of their own.
