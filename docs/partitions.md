# Partitions

This page describes what a controller of Tenko DDI does when it loses contact with the quorum of its cluster, and what happens when the contact is back: how it marks its answers as stale, which requests it refuses and how, how a person keeps an IPAM change for later in the controller's local queue, how the queue is settled after the heal, and what probes, `dns` and `dhcp` nodes do meanwhile. It is for an administrator who runs three controllers, possibly at different sites, and for a developer of a client of the API. The decisions behind it are in [ADR 0013](adr/0013-partitions.md); the cluster itself, its quorum states and the setting `[cluster] isolation_after_ms` are in [cluster.md](cluster.md#124-writes-reads-and-quorum). The requirement is OPS-26 in [REQUIREMENTS.md](REQUIREMENTS.md). Where this page and the code differ, the code is right: the quorum gate in `crates/tenko-api/src/middleware/quorum.rs`, the queue routes in `crates/tenko-api/src/routes/queue.rs`, the queue and its drain in `crates/tenko-ipam/src/queue/`.

Contents:

1. [The isolated mode](#1-the-isolated-mode)
2. [Reading on an isolated controller](#2-reading-on-an-isolated-controller)
3. [Writing on an isolated controller](#3-writing-on-an-isolated-controller)
4. [Queueing a change](#4-queueing-a-change)
5. [After the heal](#5-after-the-heal)
6. [Probes, DNS and DHCP nodes](#6-probes-dns-and-dhcp-nodes)
7. [Files, limits, audit and error codes](#7-files-limits-audit-and-error-codes)
8. [What this does not do](#8-what-this-does-not-do)

## 1. The isolated mode

The controllers form one Raft group. A write commits only when a majority of the voters (two of three) has it, so a partition never produces two versions of the data: the side with the majority goes on as before, the other side cannot commit anything, and after the heal it catches up from the log or a snapshot. There is nothing to merge.

A controller is in the isolated mode while its quorum state is `electing` (no leader is known) or `isolated` (no contact with a quorum for `[cluster] isolation_after_ms`, 3 seconds by default). A single controller (`single`) and a member in contact with a quorum (`healthy`) are never in it. The state is in `GET /api/v1/system/status` (`store.quorum`) and `GET /api/v1/cluster/members`, and every change of it is a `cluster.quorum` event on the `cluster` topic of the event stream, so the UI shows a banner with the time since the controller lost contact.

## 2. Reading on an isolated controller

Reads keep working: lists, objects, searches, the prefix tree, the audit log and the event stream are served from the controller's local copy, which stops at the last revision it applied. Every API answer of a controller in the isolated mode carries the header

```
Tenko-Staleness: since=2026-10-11T12:00:00Z; revision=4711
```

`since` is when the controller lost its leader or its quorum, `revision` the revision of its local copy (for `electing`, the revision it has; for `isolated`, the last one it applied). The UI shows the age in its status bar. The command-line client prints one warning on standard error when the controller it talks to sends the header:

```
warning: https://ddi.example.test:8443 is cut off from its cluster since 2026-10-11T12:00:00Z (4 min); it answers from its copy at revision 4711 and refuses changes until it is back (IPAM changes can be queued, see docs/partitions.md)
```

Sessions keep working on the isolated controller, because they are read from the local copy; signing in, which writes a session, does not.

## 3. Writing on an isolated controller

A quorum gate in the API refuses every request that would write, after authentication and before anything is planned or recorded:

```
HTTP/1.1 503 Service Unavailable
Retry-After: 15
Tenko-Staleness: since=2026-10-11T12:00:00Z; revision=4711
Content-Type: application/problem+json

{ "code": "cluster.no_quorum", "status": 503,
  "params": { "state": "isolated", "since": "2026-10-11T12:00:00Z",
              "revision": "4711", "queueable": "true" }, ... }
```

- `Retry-After` is 5 seconds while an election runs (it usually ends within seconds) and 15 seconds while the controller is isolated.
- `queueable` says whether `POST /api/v1/queue` takes the same request (section 4).
- A request that writes is one with a method other than `GET`, `HEAD` and `OPTIONS`. Three kinds pass the gate because they write nothing to the store: a dry run (`?dry_run=true`) of an operation that takes one, which plans against the local copy and answers the plan; `POST /api/v1/queue`; and `DELETE /api/v1/queue/{id}`.
- The gate is a courtesy, not the protection: a write that reaches the store while the controller cannot commit fails there with 503 `sys.store.no_quorum`.

The other controllers, on the majority's side, accept writes as usual. A client that can reach one of them, or a load balancer that sends the request elsewhere, can simply retry there.

## 4. Queueing a change

A person working on the isolated side can keep an IPAM change instead of losing it. The UI offers "Queue this change" in the dialog of the 503 answer; a script sends the request it would have made to `POST /api/v1/queue` as data:

```json
{
  "method": "PATCH",
  "path": "/addresses/0192f0c4-0000-7000-8000-00000000000a",
  "query": "acknowledge=ipam.address.in_supernet",
  "body": { "status": "reserved", "description": "printer, floor 2" },
  "if_match": "\"4702\""
}
```

The controller translates the request into the planner commands its endpoint would build, checks the caller's rights as that endpoint does, plans it against the local copy and keeps it. The answer (201) is the queued item with that plan:

```json
{ "id": "0192f0d1-...", "queued_at": "...", "queued_on": 3, "method": "PATCH",
  "path": "/addresses/0192f0c4-...", "summary": { "action": "update", "kind": "address", "key": "192.0.2.10" },
  "plan": { "base_revision": 4711, "changes": [ ... ], ... },
  "expires_at": "...", "state": "queued" }
```

**What can be queued:** creates, changes, deletes, restores and bulk changes of tenants, VRFs, sites, VLANs, prefixes, ranges (`POST /prefixes/{id}/ranges`), addresses, hosts and interfaces (`POST /hosts/{id}/interfaces`). A request that would fail on the local copy (a validation error, a duplicate, a missing object, a refused right) is refused at once with the endpoint's own answer, so nothing is queued that could not apply even here.

**What cannot be queued** (422 `queue.not_queueable`): dry runs (send them to the endpoint, they pass the gate), the next free address or prefix (the outcome depends on what the majority allocated meanwhile), custom field definitions, moves, proposals and adoption policies, VLAN provisioning, imports, and every write outside IPAM: settings, users, access, secrets, connectors, nodes, the cluster itself. These wait until the controller is back, or go to a controller on the majority's side.

**Who:** only people, through a session or a token of a user. The queue is the controller's own: items live on that controller only, are listed by `GET /api/v1/queue` (the caller's own items, oldest first, with `state` `queued`, `applying` or `expired`) and can be withdrawn with `DELETE /api/v1/queue/{id}` until the controller settles them. An item expires 7 days after it was queued. Creates keep the identifiers chosen when they were queued.

Each item is planned against the local copy alone: a queued change does not see an earlier queued change. Queueing the creation of a host and then a change of that host is refused, because the host does not exist in the copy; queue the host with its interfaces and addresses in one bulk change instead.

## 5. After the heal

When the controller is in contact with a quorum again, it catches up (it reads through the leader before it plans anything) and settles its queue, oldest item first. It also tries every 30 seconds while items wait, and at start for items from before a restart. For each item:

1. The commands are planned again against the current state, as `System { component: ipam, on_behalf_of: <author> }`.
2. The plan is checked with the author's rights at that moment: a disabled account, a revoked token, a role or scope the author lost, or a sign-in requirement the original session no longer meets refuses it.
3. The new plan is compared with the plan made when the item was queued: the same objects, actions and changed fields with the same old and new values, and the same warnings. A change of another field of the same object meanwhile does not count; a change of a field the item changes does, and so does an `If-Match` revision that no longer matches.
4. **Unchanged:** the plan applies as one inline job on the author's behalf. Its audit records name the principal `system:ipam` acting for the author and carry the context `queued_change`, `queued_at`, `queued_on` (the controller) and `original_session`. The item is applied under the idempotency key `queue-<id>`, so a drain interrupted after the commit never applies it twice.
5. **Anything else:** the item is not applied and becomes a conflict with the reason: `queue.plan_changed` with both plans, the planner's error (for example `ipam.address.duplicate` or `ipam.revision_mismatch`), or the authorization error (`auth.forbidden`, `auth.out_of_scope`). An item that expired before the heal becomes `expired` (`queue.expired`).

A store error that says "not now" (the quorum lost again, a timeout) stops the drain and leaves the rest queued for the next attempt.

Nothing applies silently: every settled item, applied ones included, becomes a record in the table `ipam.queued_changes`, which replicates like every IPAM table. Its author lists them on any controller:

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/queue/conflicts` | The caller's settled changes, oldest first: `state` (`applied`, `conflict`, `expired`), the request, the queued plan, the current plan, the conflict as problem details (`code`, `status`, `title`, `detail`, `params`) and the record's `revision` (for an applied change, the revision of the change) |
| `POST /api/v1/queue/conflicts/{id}/reapply` | Plans the stored commands now, as the caller, and applies them; answers as the original endpoint would (the object with `ETag`, or the bulk answer). `?dry_run=true` answers the plan only; `?acknowledge=` adds acknowledgements to those of the original request. The `If-Match` of the original request is dropped, since the caller confirms against the current state; an `If-Match` on this request takes its place for a single-object change. The record goes once the change applied |
| `DELETE /api/v1/queue/conflicts/{id}` | Discards a record: a conflict the author gives up, or an applied change the author has seen |

The UI shows the local queue and these records with their conflicts. A re-apply of an `applied` record answers 409 `queue.changed`.

## 6. Probes, DNS and DHCP nodes

- **Probes** keep scanning. A controller without quorum refuses `Observations.Ingest` with `cluster.no_quorum`; the probe keeps the batch in its disk buffer and tries the next controller it knows, so a probe that can still reach a controller of the majority delivers there, and one that reaches none delivers after the heal. The in-process probe of an isolated controller keeps its batches in the relay buffer. The details, including configuration and commands, are in [node-sync.md](node-sync.md#10-what-a-partition-does). Observations are facts, not intent: they merge per source as in [reconciliation.md](reconciliation.md) and need no queue.
- **`dns` and `dhcp` nodes** serve from the configuration they hold whatever the controllers' state (OPS-28). DHCP leases across a partition are merged by the DHCP failover protocol with MCLT (Slice 12), not by this mechanism; a serving node publishes its leases to the controllers' store after the answer, and the publications wait on the node while no controller is reachable (ADR 0025).

## 7. Files, limits, audit and error codes

| Item | Value |
|---|---|
| Queue directory | `<data_dir>/queue/`, one file `<id>.json` per item, mode `0600` in a `0700` directory on Unix; written to a temporary file and renamed, so an item is complete or absent after a crash. A file that cannot be read is moved aside to `<id>.json.bad` and logged |
| Items per controller | 1,000 (507 `queue.full`) |
| Size of one item | 4 MiB (413 `queue.too_large`) |
| Expiry | 7 days after queueing |
| Retry of a waiting queue | every 30 seconds while the controller accepts writes |
| `Retry-After` of a refused write | 5 seconds while electing, 15 while isolated |

The queue writes no audit record while the controller is isolated (it cannot write any); the applied change carries the queue context in its own audit records (section 5), and the record of every settled item stays in `ipam.queued_changes` until its author discards it. A re-apply is audited as the IPAM write it is.

| Code | Status | Meaning |
|---|---|---|
| `cluster.no_quorum` | 503 | The controller is in the isolated mode and the request would write; params `state`, `since`, `revision`, `queueable` |
| `queue.not_isolated` | 409 | `POST /queue` on a controller that accepts writes: send the request itself |
| `queue.not_queueable` | 422 | The request is not one the queue takes (section 4) |
| `queue.not_a_person` | 403 | Only sessions and tokens of users queue changes |
| `queue.not_found` | 404 | The caller has no such item or record |
| `queue.changed` | 409 | The item is being applied, the record was applied already, or the record changed meanwhile |
| `queue.full` | 507 | The queue of the controller is full |
| `queue.too_large` | 413 | The item is larger than 4 MiB |
| `queue.unavailable` | 503 | The server keeps no queue (the IPAM module is off) |
| `queue.io` | 500 | The queue directory cannot be read or written |
| `queue.plan_changed` | in a record | The plan after the heal differs from the queued plan |
| `queue.expired` | in a record | The item expired before the heal |

## 8. What this does not do

- **Sites that keep changing their own objects while cut off** need a site-local Raft group that owns their prefixes, scopes and zones (OPS-27, Phase 5). Until then the local queue is the only way to keep a change made on the minority's side.
- **The queue is not replicated.** A controller that never comes back takes its queue with it; its files can be read by hand (they are JSON) and the changes made again.
- **Queued items do not see each other**, and an allocation of the next free address cannot be queued (section 4).
- **Writes outside IPAM** cannot be queued; settings, users and secrets wait for the heal or go to the majority.
