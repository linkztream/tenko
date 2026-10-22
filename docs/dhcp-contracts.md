# DHCP contracts

This page lists the contracts of the DHCP module that every Phase 3 package builds on (WP7.0 of [phase-3-plan.md](plans/phase-3-plan.md), section 3): the model, the store tables, the engine traits, the API routes with their scopes, the event topic, the error codes, the audit actions, the metric families, the configuration keys, the node-sync declaration, the migration IR with the mapping of the Windows DHCP export, the differential test crate and the data format. It is for the builders of WP7.2 to WP9.5 and for reviewers who check that a package keeps to them. The decisions behind them are in [ADR 0019](adr/0019-dhcp-data-model-and-lease-path.md) and [ADR 0020](adr/0020-ddns-from-dhcp.md). It is temporary: WP7.4 folds it into `docs/dhcp.md`. Where this page and the code differ, the code is right: `tenko_core::dhcp` (model, tables, codes, actions, scopes), `tenko_core::ir::dhcp` (the IR), `tenko_dhcp` (engine contracts, metrics), `tenko-api` `routes::dhcp` (routes), `tenko_cluster::node_sync` (node subset, secret purpose).

Contents:

1. [Model](#1-model)
2. [Store tables](#2-store-tables)
3. [Engine contracts](#3-engine-contracts)
4. [API routes and scopes](#4-api-routes-and-scopes)
5. [Event topic](#5-event-topic)
6. [Error codes](#6-error-codes)
7. [Audit actions](#7-audit-actions)
8. [Metric families](#8-metric-families)
9. [Configuration keys](#9-configuration-keys)
10. [Node sync](#10-node-sync)
11. [Migration IR and the Windows DHCP export](#11-migration-ir-and-the-windows-dhcp-export)
12. [The differential test crate](#12-the-differential-test-crate)
13. [Data format](#13-data-format)
14. [What the code decided](#14-what-the-code-decided)

## 1. Model

`tenko_core::dhcp`. Plain data and rules: the configuration service (WP7.4) writes the configuration, the `dhcp` role (WP7.2, WP7.3) writes leases through `LeaseStore`, and the role serves from in-memory tables fed from these rows.

| Type | What it is |
|---|---|
| `DhcpSettings` | The server level (`dhcp.settings`, one row): default `LeaseTimes`, authoritative, the DDNS settings new scopes start from, conflict detection (TGL-16) and history retention (P3-Q13), both `None` to follow the security profile. Server-level options are the option set of `OptionOwner::Server` |
| `Scope` | An IPAM network with a DHCP policy (P3-Q4), keyed by its `PrefixId`: enabled, `Option<LeaseTimes>` (the server's when `None`), `Option<bool>` authoritative, `server_id`, `DdnsPolicy`, `shared_network`, `restricted` (MAC allow list, TGL-17), the admitted `classes`. `validate(&Prefix)`: the prefix is a network (`dhcp.scope.not_network` for a supernet), the server identifier of its family, valid lease times and DDNS settings, no class twice |
| `LeaseTimes` | `default_secs`, `min_secs`, `max_secs`, optional `t1_secs` and `t2_secs` (half and seven eighths when absent); `validate` (`0 < min <= default <= max <= 1 year`, `t1 < t2 < default`), `grant(requested)`, `renewal_times(granted)` |
| `DdnsPolicy`, `DdnsConflict` | ADR 0020: enabled, forward zone, reverse (PTR), TTL, `protect` or `replace`, `client_may_update_a`, `legacy_clients`, `refuse_foreign` |
| `SharedNetwork` | A superscope (`dhcp.shared_networks`): name, the interface of a directly attached link |
| `PoolSettings` | What DHCP adds to an IPAM range of role `dhcp_pool` (`dhcp.pools`, keyed by `RangeId`): classes and lease times. `validate(&Range, &Prefix)`: `dhcp.pool.not_pool`, `dhcp.pool.outside` |
| `ExclusionRange` | An explicit exclusion of a scope; the implicit ones are the prefix's `reserved` and `infrastructure` ranges and the addresses of hosts that are not `dynamic` (plan section 2.3) |
| `OptionSpace` | `dhcp4`, `dhcp6` (Slice 9) or a vendor space name (option 43 sub-options) |
| `OptionKind` | `ipv4_address`, `ipv6_address`, `ipv6_prefix`, `u8`, `u16`, `u32`, `i32`, `bool`, `string`, `fqdn` (uncompressed wire form), `classless_routes` (RFC 3442), `binary`, `empty`; with `array` a repeating kind is a list (`may_repeat`: not `i32`, `string`, `classless_routes`, `binary`, `empty`). `check(array, data)` accepts exactly what `OptionData::decode` decodes |
| `OptionDef` | A custom definition (`dhcp.option_defs`): space, code, Kea-style name, kind, array, vendor class. A code of the built-in catalog or a server-managed code is refused (`dhcp.option.code_reserved`) |
| `OptionValue`, `OptionData` | One option in wire form (`HexBytes`, as `Rdata` holds record data) and its typed view for the API (`ipv4 { values }`, `unsigned`, `text`, `names`, `routes`, `binary`, ...) with `decode` and `encode` |
| `OptionOwner`, `OptionLevel`, `OptionSet` | The five levels of plan section 2.4 plus pools: `server`, `shared_network:<id>`, `scope:<prefix>`, `pool:<range>`, `policy:<id>`, `host:<interface>`; one set per owner (`dhcp.option_sets`), `to_path`/`from_path` for the API, `validate(defs)` (no code twice, every value valid), `merge` (the more specific level wins per code) |
| `CATALOG_V4`, `SERVER_MANAGED_V4` | The built-in DHCPv4 catalog of the options the server sets or a Phase 3 package names (42 entries, Kea's names; WP7.4 completes it) and the 18 codes the server writes itself (0, 255, 50 to 59, 61, 81, 82, 93, 97, 118) |
| `Class`, `Match` | A named match (`dhcp.classes`) that holds when any of its matches holds: vendor class (exact or prefix), user class, `MacPattern`, client identifier, circuit-id, remote-id, architecture (option 93), host name |
| `Policy`, `Condition`, `Join`, `Term`, `PolicyAction` | An ordered rule of a scope or of the server (`dhcp.policies`): AND or OR over terms (class, negated class, match, negated match), the action's range restriction, lease times and DDNS settings; its options are the set of `OptionOwner::Policy` |
| `Filter`, `FilterKind`, `MacPattern`, `filter_verdict` | Server-wide MAC allow and deny entries (`dhcp.filters`, DHCP-08); deny wins; `MacPattern` is six octets in hexadecimal, any of them `*`, or a prefix ending in `*` |
| `Lease`, `ClientKey`, `BindingState`, `PoolShare`, `RelayInfo`, `Fingerprint`, `DdnsState` | A DHCPv4 lease (`dhcp.leases`, key VRF and address) with the failover draft's fields: state (`free`, `active`, `expired`, `released`, `abandoned`, `reset`, `backup`), `cltt`, `ends`, `tstp`, `tsfp`, `atsfp`, node, share; host name, FQDN, DDNS outcome, fingerprint, relay information, the observation time |
| `ClientKey::identity`, `write_identity` | The client identity of RFC 4361 and RFC 6842 as octets: `1` and option 61 when sent, else `0`, `htype` and `chaddr`; the second part of the key of `dhcp.leases.by_client`; `write_identity` writes it into a stack buffer of `MAX_IDENTITY` (256) octets |
| `LeaseRef`, `LeaseEvent`, `LeaseEventKind` | The client index value; the history row (`granted`, `renewed`, `rebound`, `released`, `declined`, `expired`, `reclaimed`, `conflict`) |
| `Lease6`, `Lease6Kind` | The DHCPv6 lease of Slice 9 (IA_NA or IA_PD, IAID, DUID, the RFC 6939 link-layer address), declared now so that this phase's format holds its values; no table stores it yet |
| `ReservationCandidate`, `ReservationWarning`, `check_reservations` | The derived reservations' check: a reserved host without identity (IPAM-18), an address or a client reserved twice (IPAM-23); a reservation inside a pool is allowed and wins |
| `DhcpScope` | The scopes `dhcp.read` and `dhcp.write`, `required(action, kind)` |
| `scope_object`, `server_object` | The authorization objects: a scope is `dhcp_scope` with its prefix's id; the server-wide configuration is the `dhcp_scope` singleton |

The tests that hold the model: the unit tests in `crates/tenko-core/src/dhcp/tests.rs`, the property tests in `crates/tenko-core/tests/dhcp_model.rs` (wire-form round trips of every option kind, check agreeing with decode on arbitrary octets, owners, MAC patterns and filters, lease times, client identities, the merge, the reservation check, CBOR and JSON round trips of the rows), and `crates/tenko-core/src/ir/dhcp.rs`.

## 2. Store tables

All in the namespace `dhcp` of the replicated store; the constants are `tenko_core::dhcp::tables`.

| Table | Key | Value | Writer |
|---|---|---|---|
| `dhcp.settings` | `()` | `DhcpSettings` | WP7.4 |
| `dhcp.scopes` | `PrefixId` | `Scope` | WP7.4 |
| `dhcp.shared_networks` | `SharedNetworkId` | `SharedNetwork` | WP7.4 |
| `dhcp.pools` | `RangeId` | `PoolSettings` | WP7.4 |
| `dhcp.exclusions` | (`PrefixId`, `ExclusionId`) | `ExclusionRange` | WP7.4 |
| `dhcp.option_defs` | `OptionDefId` | `OptionDef` | WP7.4 |
| `dhcp.option_sets` | `OptionOwner` | `OptionSet` | WP7.4 (the host level also WP8.1) |
| `dhcp.classes` | `ClassId` | `Class` | WP7.4, WP8.4 |
| `dhcp.policies` | `PolicyId` | `Policy` | WP7.4, WP8.4 |
| `dhcp.filters` | `FilterId` | `Filter` | WP7.4 |
| `dhcp.leases` | (`VrfId`, `Ipv4Addr`) | `Lease` | WP7.2 (the role's commits, expiry) |
| `dhcp.leases.by_client` | (`PrefixId`, client identity octets) | `LeaseRef` | WP7.2, in the batch of each lease change |
| `dhcp.history` | (`Timestamp`, `VrfId`, `Ipv4Addr`) | `LeaseEvent` | WP7.2, in the batch; purged by retention |

`dhcp.leases6` and `dhcp.pd_pools` follow in Slice 9 and are additive. The plan's `dhcp.host_options` is the option set of `OptionOwner::Host` in `dhcp.option_sets` (section 14). Reservations have no table: the role derives them from `ipam.hosts`, `ipam.interfaces` and `ipam.addresses`.

## 3. Engine contracts

`tenko_dhcp`. Each contract has an in-memory reference implementation that the production one is tested against.

| Contract | Says | Reference |
|---|---|---|
| `v4::Message`, `v4::MessageBuilder` (WP7.1a) | The borrowed view over a received DHCPv4 message with typed accessors, and the reply builder into a caller's buffer; neither allocates | — |
| `feed::DhcpFeed` | `snapshot()` gives a `DhcpData` (every `dhcp` row of the node subset, the leases, and the IPAM prefixes, ranges, hosts, interfaces and addresses) at a revision; `next()` the `Delta`s in revision order (`Change` per row, whole values, idempotent) or a `Reset` after a snapshot install. The shape of DNS's `ZoneFeed` | `MemFeed` with `MemFeedHandle::publish` and `reset` |
| `image::ConfigImage` | Immutable, swapped whole: the enabled scopes (`ScopeImage`: network, VRF, lease times, pools as `PoolImage`, merged exclusions, effective options of server, shared network and scope, classes, DDNS), the reservations by identity and by address, the filters, classes and policies. `select(addr)` (the most specific network, for link selection, option 118, `giaddr` or the interface), `siblings`, `reservation`, `reserved_at`, `ScopeImage::is_excluded`, `is_dynamic`, `verdict`; none allocates | `ImageBuilder`; the build from `DhcpData` is WP7.4's |
| `lease::LeaseTable` | `get(vrf, addr)`, `by_client(scope, identity)`, `apply(lease)` (keeps the row with the later `cltt`, so the role's own commit and the feed's copy give one row; the index points at a client's latest row in a scope), `remove` | `MemLeaseTable` |
| `lease::PendingChange` | The lease change as the DORA path builds it: every field inline (`InlineBytes<N>`), no heap; `to_lease(node, previous)` and `to_event(node)` build the rows on the committer side | — |
| `store::LeaseStore` | `submit(&PendingChange, Ticket)` is the hand-off: copies the change into a bounded queue, never allocates or waits on the disk; `completions` reports each ticket committed (with its revision) or refused; `accepting` is false while the store refuses (P3-Q14). Production: the store through the coalescer (WP7.2); the fallback of P3-Q1 would be a second implementation | `MemLeaseStore` (`with_capacity`, `commit`, `set_refusing`, the committed rows, index and history as the oracle) |
| `allocator::Allocator` | `pick(&Request) -> Option<Choice>`: reservation, then the client's unexpired lease, then the requested address, then a free pool address; free means in a pool, not excluded, not another client's reservation, no other client's binding, no other client's offer (`OfferHold`), owned (`PoolOwnership`) | `ReferenceAllocator` (address order; WP7.3 walks a hashed order and keeps every rule) |
| `allocator::PoolOwnership`, `grant_time`, `PartnerLimit` | Which addresses the node may hand out (`SingleNode`: all); the lease time, capped by the partner's acknowledged end plus the MCLT in Phase 5 | `SingleNode` |
| `allocator::OfferHold` | Offers held in memory for their lifetime; a DISCOVER writes nothing | `NoOffers` (WP7.2 builds the hold) |
| `probe::ConflictProbe` | `available()`, `probe(addr, timeout)` -> `Clear`, `InUse { mac }`, `Unavailable` (P3-Q7, at most about 300 ms) | `MemProbe`, `NoProbe` |
| `ddns::DdnsQueue` | `enqueue(DdnsRequest)` after the commit, never inside it (ADR 0020); bounded, `QueueFull` is dropped and counted | `MemDdnsQueue` |
| `fingerprint::Fingerprinter` | `fingerprint_of(&Message)` (options 55, 60, 77, 81, 93) and `classify` to an `OsGuess` with a confidence (P3-Q15) | `RuleTable` (first match), `NoFingerprinter` |
| `metrics` | The families of section 8 | — |

The no-allocation rule: `crates/tenko-dhcp/tests/alloc.rs` runs the codec's sections (WP7.1a) and then the DORA path of `tests/dora/mod.rs` up to the commit hand-off: parse, scope selection, the client identity, the filters, the reservation and lease lookups, the reference allocator, the `PendingChange`, `LeaseStore::submit`, and the OFFER or ACK into a stack buffer, over the fixture requests: zero allocations, reallocations and bytes. The same path with a `LeaseStore` whose `submit` boxes the change must fail the section, and the test asserts that it does, so the guard is known to bite. WP7.3 replaces the skeleton `dora` with the engine and keeps the section. The other tests: `tests/contracts.rs` (the table, the store, the feed, the image, the allocator's rules against an oracle, the probe, the queue, the fingerprinter).

## 4. API routes and scopes

Under `/api/v1`; every operation is declared with its request and answer types and, until its package builds it, checks the caller's scope and answers 501 `sys.not_implemented`. The `/dhcp` and `/nodes/{id}/dhcp` routes belong to the DHCP module (OPS-25), `/ipam/reconcile` to the IPAM module; a server without the module registers none of them.

Scopes (ADR 0015, ADR 0019 point 10): `dhcp.read` reads the configuration and the leases, `dhcp.write` changes the configuration and releases leases. The viewer holds `dhcp.read`, the operator and the administrator both, the auditor none. A scope (`dhcp_scope`, with the prefix's id) follows its prefix's scoped grants (IAM-01); `dhcp_class`, `dhcp_policy`, `dhcp_option_def` and `dhcp_filter` are global-only for grants, as the DNS kinds are; the server-wide configuration (settings, shared networks, server-level options and policies, export) is the `dhcp_scope` singleton, which only global roles reach.

| Endpoint | Scope | Package |
|---|---|---|
| `GET`, `PUT /dhcp/settings` | read, write | WP7.4 |
| `GET`, `POST /dhcp/scopes`; `GET`, `PATCH`, `DELETE /dhcp/scopes/{prefix}` | read, write | WP7.4 |
| `GET /dhcp/scopes/{prefix}/utilization`, `GET /dhcp/scopes/{prefix}/effective-options?mac=&client_id=&vendor_class=&user_class=` | read | WP7.4 |
| `GET`, `POST /dhcp/scopes/{prefix}/exclusions`; `DELETE /dhcp/scopes/{prefix}/exclusions/{id}` | read, write | WP7.4 |
| `GET`, `POST /dhcp/shared-networks`; `GET`, `PATCH`, `DELETE /dhcp/shared-networks/{id}` | read, write | WP7.4 |
| `GET /dhcp/pools`; `GET`, `PUT`, `DELETE /dhcp/pools/{range}` | read, write | WP7.4 |
| `GET /dhcp/option-catalog` | read | WP7.4 |
| `GET`, `POST /dhcp/option-defs`; `GET`, `PATCH`, `DELETE /dhcp/option-defs/{id}` | read, write | WP7.4 |
| `GET /dhcp/option-sets`; `GET`, `PUT`, `DELETE /dhcp/option-sets/{owner}` | read, write | WP7.4 (the host level with WP8.1) |
| `GET`, `POST /dhcp/classes`; `GET`, `PATCH`, `DELETE /dhcp/classes/{id}` | read, write | WP7.4, WP8.4 |
| `GET`, `POST /dhcp/policies`; `GET`, `PATCH`, `DELETE /dhcp/policies/{id}` | read, write | WP7.4, WP8.4 |
| `GET`, `POST /dhcp/filters`; `GET`, `PATCH`, `DELETE /dhcp/filters/{id}` | read, write | WP7.4 |
| `GET /dhcp/reservations`, `GET /dhcp/reservations/{interface}` (read view; writes go to the IPAM host routes and `PUT /dhcp/option-sets/host:{interface}`) | read | WP8.1 |
| `GET /dhcp/leases`, `GET /dhcp/leases/{addr}` (audited `dhcp.lease.read`) | read | WP7.2, WP7.5 |
| `POST /dhcp/leases/{addr}/release` | write | WP7.2, WP7.5 |
| `GET /dhcp/history` (audited `dhcp.lease.read`) | read | WP7.2 |
| `GET /dhcp/export?format=kea` (audited `dhcp.export`) | read | WP9.3 |
| `GET /nodes/{id}/dhcp`; `GET /nodes/{id}/dhcp/leases`; `POST /nodes/{id}/dhcp/leases/{addr}/release`; `GET /nodes/{id}/dhcp/history` (the node commands `dhcp.leases.list`, `dhcp.lease.release`, `dhcp.history.read`) | read, write, and the action on the node | WP7.5 |
| `GET /ipam/reconcile` (the IPAM-21 view) | read of observations | WP8.2 |

58 operations: 53 under `/dhcp`, four under `/nodes/{id}/dhcp`, one under `/ipam`. The request and answer types are in `crates/tenko-api/src/routes/dhcp/model.rs` and the OpenAPI document. The CLI `tenko dhcp settings|scope|exclusion|shared-network|pool|option|class|policy|filter|reservation|lease|history|export` (`crates/tenko/src/client/dhcp.rs`) parses every command, validates its arguments locally and calls its route; the UI area `/dhcp` (`ui/src/dhcp/`) has the routes of plan section 3.4 with the `dhcp` message pack. The reservations block on the host page, `/ipam/reconcile`, `/settings/dhcp` and the first-run wizard's DHCP step are WP8.6's.

## 5. Event topic

`dhcp` (`tenko_core::dhcp::TOPIC`, `Topic::Dhcp`): every change of a `dhcp.*` table, with `dhcp.scopes` rows carried as objects of kind `dhcp_scope`. Only principals with `dhcp.read` on the server-wide object receive it, because lease events are personal data. Event kinds (`tenko_core::dhcp::events`): `dhcp.lease.changed`, `dhcp.lease.sampled` (the count of events dropped by the sampling of at most 50 a second per subscriber, built with the live lease view of WP8.6), `dhcp.config.changed`, `dhcp.conflict`, `dhcp.store_state`.

## 6. Error codes

`tenko_core::dhcp::codes`, 38 codes, stable once merged (API-08):

| Code | Status | Meaning |
|---|---|---|
| `dhcp.scope.not_found` | 404 | The prefix has no scope |
| `dhcp.scope.exists` | 409 | The prefix has a scope already |
| `dhcp.scope.not_network` | 409 | The prefix is a supernet |
| `dhcp.scope.invalid` | 400 | A scope setting is invalid (`field`, `reason`) |
| `dhcp.scope.attached` | 409 | IPAM refuses to delete a prefix a scope serves |
| `dhcp.shared_network.not_found` | 404 | No such shared network |
| `dhcp.shared_network.invalid` | 400 | A shared network setting is invalid |
| `dhcp.shared_network.in_use` | 409 | The shared network still has scopes |
| `dhcp.pool.not_found` | 404 | The range has no pool settings or does not exist |
| `dhcp.pool.outside` | 400 | A pool or a policy range lies outside its scope |
| `dhcp.pool.not_pool` | 409 | The range's IPAM role is not `dhcp_pool` |
| `dhcp.exclusion.not_found` | 404 | No such exclusion range |
| `dhcp.exclusion.invalid` | 400 | Unordered, or outside the scope |
| `dhcp.option.invalid` | 400 | Option data or a definition is invalid |
| `dhcp.option.code_reserved` | 409 | A catalog code or a server-managed code |
| `dhcp.option.unknown` | 400 | The code has no definition in its space |
| `dhcp.option_def.not_found` | 404 | No such definition |
| `dhcp.option_def.exists` | 409 | A definition of the space and code exists |
| `dhcp.option_def.in_use` | 409 | An option set uses the definition |
| `dhcp.class.not_found` | 404 | No such class |
| `dhcp.class.invalid` | 400 | The class is invalid |
| `dhcp.class.in_use` | 409 | A scope, pool or policy names the class |
| `dhcp.policy.not_found` | 404 | No such policy |
| `dhcp.policy.invalid` | 400 | The policy is invalid |
| `dhcp.filter.not_found` | 404 | No such filter entry |
| `dhcp.filter.invalid` | 400 | The filter entry is invalid |
| `dhcp.filter.exists` | 409 | An entry for the pattern exists |
| `dhcp.settings.invalid` | 400 | A server setting is invalid |
| `dhcp.lease_times.invalid` | 400 | Lease times out of order |
| `dhcp.ddns.invalid` | 400 | DDNS settings are invalid |
| `dhcp.lease.not_found` | 404 | No lease holds the address |
| `dhcp.lease.state` | 409 | The lease's state refuses the operation |
| `dhcp.reservation.no_identity` | 409 | A reserved host without MAC, client identifier or DUID (IPAM-18) |
| `dhcp.reservation.conflict` | 409 | An address or a client reserved twice (IPAM-23) |
| `dhcp.store_refused` | 503 | The store refused the lease write (P3-Q14) |
| `dhcp.node.not_dhcp` | 409 | The node does not run the `dhcp` role |
| `dhcp.module.disabled` | 409 | The DHCP module is off (OPS-25) |
| `dhcp.export.format` | 400 | Unknown export format |

## 7. Audit actions

`tenko_core::dhcp::audit`, 29 actions; each configuration change writes one in its batch (IAM-18). Lease commits of the role are not audited one by one (they are the history); operator actions on leases and every read of leases are.

`dhcp.settings.update`; `dhcp.scope.create`, `.update`, `.delete`; `dhcp.shared_network.create`, `.update`, `.delete`; `dhcp.pool.update`, `.delete`; `dhcp.exclusion.create`, `.delete`; `dhcp.option.def_create`, `.def_update`, `.def_delete`, `dhcp.option.set`; `dhcp.class.create`, `.update`, `.delete`; `dhcp.policy.create`, `.update`, `.delete`; `dhcp.filter.create`, `.update`, `.delete`; `dhcp.lease.release`; `dhcp.lease.read`; `dhcp.decline`; `dhcp.export`; `dhcp.history.purge`.

The system component `dhcp` (`SystemComponent::Dhcp`) is the principal of the role's commits, expiry, the retention service and the DDNS change sets (`system:dhcp`, ADR 0020 point 7).

## 8. Metric families

`tenko_dhcp::metrics::ALL`, 13 families; per-shard relaxed counters on the DORA path, lazy gauges on a timer (OPS-21). Counter names gain `_total` in the encoder.

| Family | Kind | Labels |
|---|---|---|
| `tenko_dhcp_packets_total` | counter | `family`, `type`, `outcome` |
| `tenko_dhcp_exchange_duration_seconds` | histogram, 50 µs to 1 s | `step` (`offer`, `ack`) |
| `tenko_dhcp_commit_duration_seconds` | histogram | |
| `tenko_dhcp_leases` | gauge (lazy) | `state` |
| `tenko_dhcp_pool_utilization` | gauge (lazy) | `scope` |
| `tenko_dhcp_naks_total` | counter | |
| `tenko_dhcp_declines_total` | counter | |
| `tenko_dhcp_conflicts_total` | counter | |
| `tenko_dhcp_probe_duration_seconds` | histogram | |
| `tenko_dhcp_ddns_total` | counter | `outcome` |
| `tenko_dhcp_ddns_queue` | gauge | |
| `tenko_dhcp_dropped_total` | counter | `reason` (`malformed`, `filtered`, `no_scope`, `pool_full`, `queue`, `store_refused`, `rate_limited`) |
| `tenko_dhcp_store_refused_total` | counter | |

## 9. Configuration keys

Node-local settings of the role in `tenko.toml`, built and documented in `deploy/tenko.example.toml` by WP7.5 (the replicated settings are `dhcp.settings`):

| Key | Default | Meaning |
|---|---|---|
| `[dhcp] listen` | none | A list of `{ address, mode = "relay" | "direct", interface }`; relay mode binds the unicast address on port 67 |
| `[dhcp] workers` | the CPU count, at most 8 | Blocking UDP workers |
| `[dhcp] offer_secs` | 10 | How long an offer holds its address in memory |
| `[dhcp.probe] timeout_ms`, `cache_secs` | 300, 600 | The conflict probe's cap and its clean cache |
| `[dhcp] proxy`, `proxy_port` | none, 4011 | Proxy DHCP listeners for boot clients (P3-Q16, WP8.4): unicast IPv4 addresses that answer PXE and HTTP boot clients without an address on the proxy port |
| `[dhcp.probe] pending` | 1,024 | The pending table's size: offers waiting for a probe (WP8.5); a full table offers unprobed |
| `[dhcp.decline] hold_secs` | 86,400 | How long a declined address stays abandoned |
| `[dhcp.decline] limit`, `window_secs` | 3, 3,600 | DECLINEs accepted per client per window; one beyond is dropped as `rate_limited` and the client keeps its lease (WP8.5) |
| `[dhcp.ddns] retries`, `backoff_ms` | WP8.3 | The DDNS worker's retries while the store refuses |
| `[dhcp.history] days` | per profile (P3-Q13) | A node-local override of the retention |
| `[dhcp.v6]` | Slice 9 | DHCPv6 listeners |

## 10. Node sync

Declared and consumed by no node in Phase 3 (plan section 2.12): `tenko_core::dhcp::tables::NODE_TABLES` (every `dhcp.*` table except `dhcp.history`) is what `tenko_cluster::node_sync::tables::role_tables_for` gives a node with the `dhcp` role; `NODE_IPAM_TABLES` (`ipam.prefixes`, `ipam.ranges`, `ipam.hosts`, `ipam.interfaces`, `ipam.addresses`) names the IPAM rows the reservations derive from, which a node receives once node sync has row filters (the prefixes with a scope, their ranges, the `reserved` hosts with their interfaces and addresses in served prefixes). The secret purpose `dhcp.failover` (`tenko_core::dhcp::FAILOVER_PURPOSE`) is in `node_sync::secrets::PURPOSES` for the `dhcp` role, for the failover shared secret of Phase 5 (IAM-16, NEVER-01).

## 11. Migration IR and the Windows DHCP export

`tenko_core::ir::dhcp::DhcpIr` (P3-Q10): a DHCP source adapter produces it beside the IPAM `Ir` and one `LossReport`; Phase 4 builds the adapters (MIG-08, MIG-12) and the import, which maps a scope onto a prefix with a `dhcp.scopes` row, a pool onto an IPAM range of role `dhcp_pool`, a reservation onto an IPAM host of mode `reserved` with its interface and address, and options onto option sets by owner. Items name each other by natural key (network, class name, host name); option values stay in the source's text form, because only the import knows the definitions that type them.

The mapping of the XML that `Export-DhcpServer -Leases` writes (the `DHCPServer` root with its `IPv4` element; `IPv6` follows with Slice 9), written against the published structure and a hand-written fixture with documentation addresses; the owner checks it against a real export on the owner's machine (plan section 9), and nothing from a real export enters the repository.

| Windows element | IR | Tenko model | Losses |
|---|---|---|---|
| `IPv4/OptionDefinitions/OptionDefinition` (`OptionId`, `Name`, `Type`, `MultiValued`, `VendorClass`, `Description`) | `IrOptionDef` (`Type`: `Byte` u8, `Word` u16, `DWord` u32, `DWordDword` binary, `IPv4Address` ipv4_address, `String` string, `BinaryData` and `EncapsulatedData` binary, `IPv6Address` ipv6_address) | `OptionDef`; a definition of a catalog code is skipped when it agrees with the catalog | A definition of a catalog code that disagrees; `DefaultValue` |
| `IPv4/OptionValues/OptionValue` (`OptionId`, `VendorClass`, `UserClass`, `Value`) | `DhcpIr.server_options` (`IrOption`) | The option set of `server`; a value with a user class becomes a server-level policy on that class with the value in its option set | Values of server-managed codes (51, 58, 59 come from lease times) |
| `IPv4/Classes/Class` (`Name`, `Type` Vendor or User, `Data`, `IsDefault`) | `IrClass` (`builtin` for the default Microsoft classes) | `Class` with one `vendor_class` or `user_class` match; built-in classes are skipped | — |
| `IPv4/Filters/Filter` (`MacAddress` with wildcards, `List` Allow or Deny, `Description`) | `IrFilter` | `Filter`; the server's filter enablement (`IPv4/AllowFilter`, `DenyFilter`) sets `restricted` on every scope when the allow list is on | — |
| `IPv4/Policies/Policy` (`Name`, `ProcessingOrder`, `Enabled`, `Condition` AND or OR, `VendorClass`, `UserClass`, `MacAddress`, `ClientId`, `RelayAgent`, `CircuitId`, `RemoteId`, `SubscriberId`, `Fqdn` criteria with `Equals`/`NotEquals`, `IPRanges`, `OptionValues`, `LeaseDuration`, DNS settings) | `IrPolicy` with `IrCondition` per criterion (`negate` for `NotEquals`), scope `None` | `Policy` with `scope: None`; a criterion becomes a `Term` (a class term for vendor and user class names, a match otherwise); several values of one criterion become an OR class | `SubscriberId`; `Fqdn` with a wildcard that is not a prefix; more than one level of nesting |
| `IPv4/Scopes/Scope` (`ScopeId`, `SubnetMask`, `Name`, `Description`, `StartRange`, `EndRange`, `LeaseDuration` as `d.hh:mm:ss`, `State` Active or Inactive, `Type` Dhcp/Bootp/Both, `Delay`, `MaxBootpClients`, `NapEnable`, `ActivatePolicies`) | `IrScope` (`cidr` from `ScopeId` and `SubnetMask`, `ranges` one pool, `lease_secs`, `active`, `delay_ms`) | An IPAM prefix (created when missing) with a `dhcp.scopes` row (`enabled` from `State`) and an IPAM range of role `dhcp_pool` whose `lease_secs` is the duration | `Delay` other than 0 (Tenko has no offer delay; split scopes are CON-05), `MaxBootpClients`, `NapEnable`, BOOTP-only scopes; `ActivatePolicies` false becomes the scope's policies disabled |
| `Scope/ExclusionRanges/IPRange` (`StartRange`, `EndRange`) | `IrScope.exclusions` | `ExclusionRange` | — |
| `Scope/Reservations/Reservation` (`Name`, `IPAddress`, `ClientId`, `Type`, `Description`, `OptionValues`) | `IrReservation` (`client` as a MAC when `ClientId` is six octets, else client identifier octets; `bootp` for `Bootp` or `Both`) | An IPAM host of mode `reserved` named after `Name` (made a host name or reported), an interface with the MAC or client identifier, its address in the prefix, and the option set of `host:<interface>` | Names that are not host names (renamed and reported); BOOTP-only reservations |
| `Scope/OptionValues/OptionValue` | `IrScope.options` | The option set of `scope:<prefix>`; user-class values become a scope policy on the class | As for server options |
| `Scope/Policies/Policy` | `IrPolicy` with `scope` the scope's network | `Policy` with `scope` the prefix | As for server policies |
| `Scope/DnsSettings` (`DynamicUpdates` Always/OnClientRequest/Never, `DeleteDnsRROnLeaseExpiry`, `UpdateDnsRRForOlderClients`, `NameProtection`, `DisableDnsPtrRRUpdate`) | `IrScope.ddns` | `DdnsPolicy`: `Never` disables; `Always` writes A and PTR (`client_may_update_a` false); `OnClientRequest` lets the client write A (`client_may_update_a` true); `UpdateDnsRRForOlderClients` is `legacy_clients`; `NameProtection` is `protect`; `DisableDnsPtrRRUpdate` clears `reverse`; the forward zone is the scope's option 15 when Tenko serves it | `DeleteDnsRROnLeaseExpiry` false (Tenko removes records on expiry when the DHCID matches, ADR 0020) |
| `IPv4/SuperScopes/SuperScope` (`Name`, the member `ScopeId`s) | `IrSuperscope` | `SharedNetwork` named after the superscope, each member scope's `shared_network` | — |
| `IPv4/Failover/Relationship` (`Name`, `PartnerServer`, `Mode` LoadBalance or HotStandby, `MaxClientLeadTime`, `LoadBalancePercent`, `ReservePercent`, `ScopeId`s, `SharedSecret`) | `IrFailover` | Kept for the report and the Phase 5 pairing; nothing is created in Phase 4 | The relationship itself (Phase 5), and always the shared secret, which never leaves the source and is entered in the vault under `dhcp.failover` |
| `Scope/Leases/Lease` (`IPAddress`, `ScopeId`, `ClientId`, `HostName`, `LeaseExpiryTime`, `AddressState` Active, ActiveReservation, Declined, Expired and the `*Pending` states) | `IrLease` (`state`; the other states are `other`) | A `dhcp.leases` row with state `active` or `abandoned` (declined), the client key from `ClientId`, `ends` from the expiry; expired leases are not imported | `other` states; leases of scopes not imported |
| `IPv4/ConflictDetectionAttempts` | — | `DhcpSettings::conflict_detection` on when above 0 (Tenko probes once) | The attempt count |
| `IPv4/NapEnabled`, `IPv4/ActivatePolicies`, the audit log settings, `IPv4/DnsSettings` at server level | — | The server-level DNS settings become `DhcpSettings::ddns` | NAP (removed from Windows), the audit log path |

## 12. The differential test crate

`dhcproto` 0.15.0 (crates.io, MIT, by BlueCat Engineering), pinned exactly in the workspace's `[workspace.dependencies]` with default features off and used by `tenko-dhcp` as a dev-dependency only (ADR 0019 point 7). Its owned decoder (`v4::Message::decode`) builds a `BTreeMap` of owned `DhcpOption` values (vectors of addresses, strings, the relay sub-options) and allocates per message, which is why it is not the production codec; it also has a borrowed, lazily decoded `v4::borrowed::Message` whose option iterator concatenates split options. It brings two crates new to the graph, `dhcproto` and the proc-macro `dhcproto-macros`; its other dependencies (`hickory-proto` 0.26 without default features, `rand` 0.10, `ipnet`, `thiserror` 2) are already in the graph. `cargo deny check` accepts it: advisories, bans, licenses and sources ok (the duplicate-version warnings of `rand` and `getrandom` were there before). How the differential test uses it (WP7.1a's acceptance, then WP7.3's corpus of captured requests): every fixture and corpus request is decoded by both codecs and the header fields, the message type, the option codes in order, the parameter request list, the client identifier, the requested address, the relay agent sub-options and the client FQDN compared; replies built by `MessageBuilder` are decoded by `dhcproto` and compared field by field with the inputs of the builder; where the two disagree on a malformed message, the test records which RFC rule decides.

## 13. Data format

The data format moves to 4 once for the phase (ADR 0019 point 11): the `dhcp` namespace of tables, actions and codes, the five DHCP object kinds and the system component `dhcp` are values a format 3 binary cannot decode, so a format 3 binary must refuse a Phase 3 data directory. The migration is empty (`crates/tenko/src/upgrade/migrations/v4.rs`): nothing stored in format 3 changes meaning; the runner commits the bump of the format record and its audit record. Its fixture is `crates/tenko/tests/fixtures/datadir/v4/`. The fixtures' size limit is raised from 4 MiB to 8 MiB in the same change (`crates/tenko/tests/upgrade_compat.rs`, `docs/upgrades.md` section 4.5): the fixtures of formats 1 to 3 held 3.42 MiB, most of it the space each redb file sets aside, and compressing them would change the committed fixtures of earlier formats and need a decompressing step. The tables later Phase 3 packages add in the namespace are additive and need no format of their own.

## 14. What the code decided

Where the code settles what the plan left to it (recorded in ADR 0019 and ADR 0020 as refinements; both stay Proposed):

- **Option sets by owner.** `dhcp.option_sets` is keyed by `OptionOwner`, one set per server, shared network, scope, pool, policy and IPAM interface. `Scope`, `SharedNetwork`, `PoolSettings`, `PolicyAction` and the plan's `HostOptions` have no `options` field: their options are the set their owner keys (`Scope::options()` gives the reference). There is no separate `dhcp.host_options` table. The configuration service deletes an owner's set in the batch that deletes the owner.
- **The depth of a condition.** A policy's condition is AND or OR over terms and a class is OR over matches: a tree of depth two, which is what the Windows export holds and what Kea's `test` expressions express (P3-Q12).
- **Exclusions under their scope.** `dhcp.exclusions` is keyed by scope and id, and the routes are `/dhcp/scopes/{prefix}/exclusions`.
- **The commit hand-off.** `LeaseStore::submit` takes a fixed-capacity `PendingChange` and returns at once; completions come back by ticket. That is how the DORA path stays allocation-free up to the hand-off while the batch (rows, index, history, observation) is built on the committer's side.
- **The client index.** `dhcp.leases.by_client` holds a client's latest row in a scope (by `cltt`, then address), so the index is the same whatever order rows arrive in.
- **Server-wide configuration.** Settings, shared networks, server-level options and policies and the export authorize on the `dhcp_scope` singleton, which scoped grants never reach.
- **The Slice 9 values now.** `OptionKind` holds the IPv6 kinds and `Lease6` exists, so Slice 9 adds tables (additive) and no new enum values (no second format bump in the phase).
- **The `UpdatePolicy` field `dhcp`** of ADR 0020 point 6 is WP8.3's: it changes the DNS zone row and its DTO, which WP7.0 leaves alone.
- **WP8.3: the option 81 flags on the lease.** `Lease.fqdn_flags` and `PendingChange.fqdn_flags` carry the flags the client sent in option 81 (S, O, E, N), so the DDNS worker knows whether the client writes its A record (`client_may_update_a`); the field has a serde default and is skipped when absent, so the data format stays 4.
- **WP8.3: `UpdatePolicy.dhcp`** is `Option<bool>`: none follows the profile (Home and Lab allow DHCP updates, Standard and Hardened do not); the DDNS outcomes of `tenko_dhcp_ddns_total` are `written`, `removed`, `refused`, `failed`, `skipped` and `dropped`, and the worker is the leader service `dhcp.ddns` following `dhcp.leases` by a store watch (`docs/dhcp.md` section 13).
