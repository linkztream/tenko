# Lease flush plan: storage never keeps a client from its lease

- Status: Proposed. The direction is the owner's decision of 2026-11-21 (F94, option A1); the open points are section 10 (LF-Q1 to LF-Q8).
- Date: 2026-11-21
- Scope: when the DHCP answer (DHCPACK, and REPLY for DHCPv6) leaves relative to the lease's write. (a) Normal mode: the answer waits for the lease's durable record in the log, which is group-committed, and no longer for the apply behind it. (b) Write-behind: while the log lags past a bound, the answer leaves from memory, the write follows, the node says so, and after an unclean restart the conflict probe is on for new addresses and DHCPDECLINE is honored. Written against `main` at `75af2f27`. Sources: [ADR 0019](../adr/0019-dhcp-data-model-and-lease-path.md) point 3, [ADR 0030](../adr/0030-durability-classes-of-the-lease-path.md) (its "next step" 2 is design (a)), [ADR 0025](../adr/0025-dhcp-failover-and-data-plane-ha.md) and [ha-plan.md](ha-plan.md) section 3.1 (Slice 12: the node store), DHCP-07 in [REQUIREMENTS.md](../REQUIREMENTS.md), E24 and M26 to M32 in [phase-3-exit.md](phase-3-exit.md), [dhcp.md](../dhcp.md) sections 8 and 14.

## 1. The problem, with the figures we have

Today the answer waits for the whole store pipeline, not only for the disk. A change goes from the worker to the hand-off queue, the committer, the coalescer, openraft, the log writer's group commit (one redb transaction with `Durability::Immediate`, one fsync per group), openraft's commit, the apply on a blocking thread (with the derived index's `absorb`), the coalescer's answer task, and back through the committer to the worker. Only the fsync makes the lease durable: the state machine applies with `Durability::None` and is made durable by a checkpoint once a second (ADR 0030 point 9). Everything after the fsync adds latency and no durability.

| Figure | Value | Where and when |
|---|---|---|
| Commit average, one worker, two VMs, final build 0.0.10 | 3.27 and 3.01 ms at 1,000/s; 9.22 and 10.05 ms at 5,000/s; 28.89 and 29.27 ms at 10,000/s; 163 and 159 ms at 15,000/s | `bench/phase3-dhcp/results/2026-10-30-e22-real-link.md` (2026-10-30) |
| The same node's fsync | idle probe p50 0.3 ms, p99 0.6 to 1.1 ms; the disk does 1,230 to 1,340 synchronous 4 KiB writes per second | same file |
| REQUEST to ACK (M28) | p50 3.02 ms, p99 23.0 ms at 1,000/s; p99 110 ms at 5,000/s; the commit almost all of it | same file; phase-3-exit M28 |
| Ceiling (M26) | 9,995 exchanges/s within 0.1 percent drops; bounded by about 65,000 rows/s applied (ADR 0031) | same file |
| The commit tail on the workstation | 87 to 98 percent of commits above 25 ms waited behind the once-a-second `sm.redb` checkpoint (stalls of 25 to 75 ms) | ADR 0030, "The tail that remains" (2026-10-30) |
| M31, DDNS end to end | names p99 699 and 777 ms, DORA p99 403 and 430 ms (stand-in, Windows, loopback) | `2026-10-22-m31-ddns.md` (2026-10-22 and 23) |
| M32, kills under load | 20 kills, 144,681 ACKs, none lost | `2026-10-22-m32-crash.md` (2026-10-22) |

So at 1,000/s about 90 percent of the commit is pipeline (3.27 ms against an fsync p50 of 0.3 ms). M31 is older than the store it blames: it was measured before WP9.6 and WP9.7 (ADR 0030 and ADR 0031), when a lease commit was 13 rows and 3.7 KB and a snapshot fired every few hundred entries. Today a lease commit is 2 rows and about 670 bytes. M31 is therefore measured again on today's `main` before anything here is built (LF0), and its result decides nothing in this plan; it is the baseline that the DDNS work is measured against.

Storage refuses a client today in four places:

1. the worker's pending slots are full: `crates/tenko-dhcp/src/server/mod.rs:974-977` (`DropReason::Queue`);
2. the hand-off queue is full: `lease/commit.rs:291-292` returns `SubmitError::Full`, `server/mod.rs:999-1001` drops;
3. the change has not committed within `commit_wait` (2 s): `lease/commit.rs:539-552` fails the ticket, the worker drops;
4. the store refuses writes: the refusal gate (`lease/refusal.rs`, P3-Q14).

A fifth, `HeldByOther` in `lease/batch.rs:142-144`, is correctness and stays. Design (a) removes most of the latency that leads to 1 to 3. Design (b) removes 1 to 3 as reasons to stay silent while the store is only slow. Point 4 stays (LF-Q7).

The owner's note on writes: small separate writes each cost whole filesystem blocks. Both designs keep one durable write per group and add none per lease; section 2.5 rejects a second lease journal for the same reason.

## 2. Design (a): the answer waits for the log record, not the apply

### 2.1 What changes in the store

The store gets one call beside `propose` in the `Store` trait (`crates/tenko-store/src/api.rs:1231-1251`):

`propose_logged(batch, logged: oneshot::Sender<()>) -> Result<Committed, StoreError>`

It is `propose` and also fires `logged` as soon as the batch can no longer be lost or refused. The default implementation, which `MemStore` uses, fires `logged` after the commit, so every store other than the Raft store keeps today's behavior. The Raft store fires it at the group commit when all three of these hold:

- **the batch cannot fail at apply.** It has no preconditions and no idempotency key, and it passed `validate` at propose (`raft/mod.rs:2086`). A lease batch is such a batch (`lease/batch.rs:135-179` adds neither). Every other batch gets `logged` together with the commit;
- **the group has one voter.** openraft's effective membership names this node as its only voter. It is read after the flush, so a voter added in between makes the batch wait for the apply;
- **the log entry carrying it is durable.** `commit_group` (`raft/log.rs:442-475`) has committed the redb transaction with the entry in it.

How the flush reaches the batch:
- `Queued` (`raft/coalescer.rs:48-53`) gains `logged: Option<oneshot::Sender<()>>`.
- `Proposal` (`raft/types.rs:62-72`) gains `#[serde(skip)] seq: u64`, which the coalescer sets for each entry it hands to `client_write_ff` (`coalescer.rs:220`). It is skipped by serde, so the log and wire formats do not change, followers read it as 0, and `deny_unknown_fields` is not touched.
- `append` (`log.rs:739-768`) sees the leader's own `Entry` values before it encodes them and records the highest `seq` of each `WriteOp::Append`. After a successful `write_group`, `commit_group` publishes it on a `tokio::sync::watch` shared with the coalescer.
- `answer` (`coalescer.rs:232`) fires the `logged` senders of its entry when the watch passes the entry's `seq`, then awaits the response as today and sends each `Committed`.
- A failed group commit fires nothing.

The builder checks first that openraft 0.9.25 hands the leader's own entries to `append` without encoding them on the way. If it does not, the same `seq` travels in a side map keyed by log index, which `append` fills from `entry.log_id.index`.

What stays: the coalescer's four entries in flight (`max_inflight_entries`) are still released at the answer, that is after the apply. Entries that are logged but not applied therefore stay bounded at 4 × 128 batches, and an apply that falls behind still slows new answers. (a) moves latency. It does not raise the ceiling, which the apply rate sets (M26).

### 2.2 What changes in the DHCP committer

In `Running::start` (`lease/commit.rs:510-600`, and the same in `v6/lease/commit.rs:454-530`), `store.propose(batch)` (`:544`) becomes `propose_logged`. When `logged` fires, the ticket completes: the worker sends the ACK, and `tenko_dhcp_commit_duration_seconds` now measures the time from the hand-off to the answer. Everything else stays at the commit, where it is today:
- the row goes into the role's table at the commit's revision (`:565`);
- the derived history row is pushed (`:571-578`);
- `gate.committed()` is called;
- the address and the client stay in the committer's busy set (`:473`).

The `Completion` outcome (`crates/tenko-dhcp/src/store.rs:58-63`) becomes `Result<Answered, CommitError>`, where `Answered` is `Committed(Revision)`, `Logged` or `Behind` (for section 3). The two servers read only `is_err` (`server/mod.rs:1052`, `v6/server.rs:710`).

Why the table is not filled at the flush. A row applied at `Revision::ZERO` is ordered against the feed's copies by `cltt` alone (`lease/table.rs:251-258`). A DDNS outcome rewrites the lease row with the same `cltt` (`ddns/worker.rs:922-965`), so a tie could put an older row over a newer one. Leaving the table to the commit keeps one ordering rule. The window between the ACK and the table holding the row is the apply, a few milliseconds, and it is covered:
- a second change of the same address or client waits in the busy set until the first has applied, and is then built from the table. This is the last guard of `batch::build`, which refuses `HeldByOther`;
- a new client's address is in the offer hold for `offer_secs` (10 s; `lease/offer.rs`), so no other DISCOVER is offered it;
- a REQUEST that reached the address without an offer is refused by that guard.

`StoreLeases::derived().flush()` (`lease/derived.rs:301`) first waits for the committer's logged changes to apply, so that a flush after a completion still covers its history row (ADR 0030 point 2; the operator's release and the tests rely on it). The 2 s `commit_wait` stays until (b) replaces it (section 3.2), but now measures the time to the log record.

### 2.3 Why (a) is safe on a single voter

1. **The record is the commit.** Raft commits an entry once a majority of voters hold it durably. With one voter, its own fsync is that majority, and openraft commits on the `LogFlushed` callback that the same `commit_group` fires (`log.rs:469`). No other node can lead, so no other node can truncate the entry. A voter added later receives the log from this one.
2. **The apply cannot refuse it.** The apply is deterministic. A lease batch has no precondition and no idempotency key, and its size was validated at propose. An error inside the apply stops the store (`sm.rs:475-540`, `stopped_at`). That is the same failure as a dead disk, and the next start replays the entry from the log.
3. **A start applies every logged entry before the role reads.** The state machine replays the log from its last checkpoint (ADR 0030 point 9). On one voter the node elects itself and commits the rest of its log; the persisted `committed` value may lag, but that is harmless (`log.rs` module notes). The role rebuilds its table after the store has opened. The crash test of section 6 proves it with kills between the flush and the apply.
4. **The durability is today's.** Today's ACK waits for exactly this fsync and then for an apply that writes nothing durable. (a) removes the wait for the apply and adds no new loss window.

### 2.4 More than one voter, and the Slice 12 node store

- **A controllers' group of more than one voter.** The leader's flush is not a commit: a new leader can truncate an entry that only the old leader held. The store therefore answers lease batches there at the apply, as today. Nothing else is needed, because the `dhcp` role on a controller of a multi-voter cluster already breaks CONTRIBUTING rule 5 (a quorum on the DORA path; ADR 0025, Context), and Slice 12 moves the lease authority off that group.
- **The node store (ha-plan section 3.1, WP12.2).** It is a one-voter instance of `tenko-store`, never a member of the controllers' group. (a) lives in `tenko-store`, so the node store answers leases at its flush with no further work, on a controller node and on a data-plane node alike. The publication to the controllers' store (ha-plan section 3.9) is batched (every 100 ms or 1,000 rows) after the answer, so a lease still costs one grouped fsync before the ACK.
- **A pair (WP12.3).** A binding update goes to the partner after the local commit, in revision order, as ha-plan section 3.8 says. With (a) the answer may leave before the update is sent. That is HA-Q3's lazy update, already bounded by the MCLT (maximum client lead time). The 50 ms wait for a new binding's acknowledgment (ADR 0025 point 5) is unchanged.

### 2.5 Rejected for (a)

- **A table row at `Revision::ZERO` at the flush.** It is rejected for the `cltt` tie of section 2.2.
- **A separate append-only lease journal**, the full version of ADR 0019 point 4. Slice 12's node store is that journal. A third file on a controller node would add a second fsync per group: the small separate writes the owner warned of.
- **A fixed flush period**, dhcpd's delayed ACK. It delays a lone lease at idle, while the adaptive group commit already batches under load.
- **Answering at the commit index on a multi-voter group.** openraft 0.9 gives no per-entry commit signal short of the apply, and Slice 12 makes this case go away.

## 3. Design (b): write-behind while the log lags

### 3.1 The rule

A change is answered no later than its answer bound after its hand-off. If its log record is not durable by then, the answer leaves from memory and the write follows. The same holds when there is no room to wait: a full slot table or a full hand-off queue. There is no separate mode to enter and leave. Each change is either answered at its record (a) or written behind (b), and the node is *writing behind* while at least one answered change is not yet logged.

### 3.2 The code places

1. **The bound replaces `commit_wait`.** In `lease/commit.rs:539-552` (and `v6/lease/commit.rs:481-500`) the deadline `queued.at + ack_wait` no longer fails the ticket. It completes the ticket as `Behind` and the commit goes on. The field is renamed `ack_wait` and set to 500 ms (section 3.3). When the commit lands, the committer applies the row and pushes history as for any commit, and releases the address hold of item 3.
2. **No room is no reason to drop.** In `hand_off` (`server/mod.rs:960-1005`), when no slot is free (`:974`) or `submit` answers `Full` (`:999`), the worker hands the change to `StoreLeases::submit_behind`. That call puts it into the same queue, beyond the normal capacity, up to a second capacity of the same size, with a ticket that names no slot. The worker then holds the address (item 3) and sends the reply from its scratch buffer at once. It allocates nothing, so `tests/lease_alloc.rs` covers this path. Only past both capacities is the request dropped as `queue`, as today.
3. **The address stays the client's until its row lands.** A change written behind holds its address in the offer hold for that client (`OfferTable`, `lease/offer.rs`). The hold ends at the lease's end, and the committer releases it when the row has applied (`OfferTable::release`, `offer.rs:108`; `StoreLeases` gets the server's offer table). A hold refused by a full offer table drops the request as today. The table is sized from the image with room for the second capacity (dhcp.md section 10.8). Why the offer hold and not the lease table: the table's ordering stays as in section 2.2, and the hold is in memory, exactly as long-lived as the promise it guards.
4. **The commit loop sends `Behind` answers like commits** (`server/mod.rs:1025-1060`), takes the hold of item 3, and counts them.
5. **The refusal gate stays** (LF-Q7). A store that refuses writes is not lagging: write-behind into it would grow without end and promise leases that never land. A change written behind and then refused is counted as lost (section 4). Its hold keeps the address from other clients until the lease's end, and the clean-close marker is kept at the stop (section 5).
6. **A `HeldByOther` on a change written behind** cannot happen while item 3 holds. If it does, it is counted as lost and logged as an error, and the tests assert zero.

Loss window: the changes answered and not yet logged, at most the second capacity plus the 512 in flight. At today's largest queue (4,096) that is 4,608 changes: about 0.5 s of load at 10,000/s, 4.6 s at 1,000/s.

### 3.3 The bound and how it is chosen

| Bound | Proposed | How it is chosen |
|---|---|---|
| `ack_wait`, the time from the hand-off to the answer | 500 ms, a constant in `CommitSettings`, not a setting (the tunables rule) | Lower limit: the normal path must never cross it, so it is at least ten times the p99.9 from the hand-off to the answer at the node's sustained ceiling, measured after (a) in LF3. Before (a) the commit p99 at 5,000 to 10,000/s sits in the "at most 250 ms" bucket (2026-10-30), which is why the bound is set only after LF3. Upper limit: the answer must never cause a retransmission. RFC 2131 section 4.1 has the client retransmit after about 4 s (randomized by ±1 s, so 3 s at the earliest), and M28's line is a p99 below 100 ms, so the bound stays below 1 s. LF3 confirms 500 ms or names the figure |
| The second capacity, the changes that may be written behind | The hand-off queue's own sized capacity again (dhcp.md section 10.8: 256 to 4,096), about 6.6 MiB at the cap | It is the loss window of an unclean stop. It is sized with the rule that already sizes the queue, so it is one fact in one place and needs no new setting. Beyond it a stalled disk is a failure to show, not to hide (LF-Q3) |

## 4. What the operator sees

| Kind | Name | When |
|---|---|---|
| Counter | `tenko_dhcp_write_behind_total{family}` | An answer left before its write |
| Gauge | `tenko_dhcp_write_behind_pending{family}` | Answered changes not yet logged |
| Counter | `tenko_dhcp_write_behind_lost_total{family}` | A change written behind that the store refused, or `HeldByOther` |
| Histogram | `tenko_dhcp_commit_duration_seconds` (kept) | From the hand-off to the answer (now the log record, or the bound) |
| Health finding, warning | `dhcp.lease.write_behind` | Raised at the first answer written behind, with the time, the count and the most pending; cleared when nothing is pending. Says: "The disk is slower than the clients: N leases were answered before they were written; a crash now would lose at most M." |
| Health finding, error | `dhcp.lease.write_behind_lost` | A change written behind was lost. It stays until the next clean start, because the next start probes |
| Health finding, warning | `dhcp.lease.unclean_restart` | The start found the marker (section 5). Says until when new addresses are probed and with which method, or, as an error, that no probe can run on this node |
| Audit | `dhcp.lease.write_behind` | One record per episode (from the first pending to none pending): the start, the end, the count, the most pending, the lost |
| Audit | `dhcp.lease.recovery` | An unclean start: the window's end and the probe method |
| Log | warning lines | The start and end of an episode, an unclean start |

The audit actions need English and Swedish labels in `ui/i18n/<language>.d/labels.xlf` (the label catalog test). The findings use the existing health row display. The notification rules can route them like any finding.

## 5. The unclean restart: the marker and the probe

### 5.1 The clean-close marker

- **The file.** `<data_dir>/dhcp.open`, named in one place: a new `crates/tenko-dhcp/src/lease/recovery.rs`. It is written with `tenko_store::fs::write_private` (temporary file, fsync, rename, directory sync) before the role binds its first listener, so it is durable before the first answer.
- **Removal at a clean stop.** The file is removed only after the listeners are closed, the hand-off queue has drained, every change has committed, the derived writer has flushed and `write_behind_lost` is zero. A stop that leaves any of these open keeps the file.
- **The next start.** A start that finds the file is unclean.
- **Never parsed.** Its existence is the whole signal, so its content is ignored: anyone able to write it can only turn probing on, and anyone able to write `<data_dir>` already holds the store (ADR 0023's threat model is unchanged).
- **Fail-safe edges.** A removal that a power loss undoes, or a backup that copied a running node's marker, only causes an extra probe window. The first start after the upgrade finds no file, which is right: the old binary never answered ahead of the write.

### 5.2 The probe after an unclean start

- **What it covers.** Every unclean start, not only one after write-behind (LF-Q4). It also covers a disk or hypervisor that acknowledges a flush it did not make, such as `cache=unsafe` or a drive without power-loss protection. It needs no extra write at the moment the disk is slow.
- **How long.** The window lasts from the start until the longest lease time of the scopes in the first configuration image (LF-Q5). By then every lease a crash could have lost has ended or been renewed.
- **What it forces on.**
  - The window is a field of `ConflictSettings` (`conflict/mod.rs:157-198`), and `Conflicts::effective` (`:320-327`) answers true until it ends, whatever `dhcp.settings.conflict_detection` and the profile say (LF-Q6).
  - The probe is the same `ScanProbe` without the `probe` role: `scan::choose` (`scan.rs:105`) takes `probe_role || unclean`, called from `crates/tenko/src/serve/dhcp.rs:363`. It uses what the service already holds: ARP with `CAP_NET_RAW` on the link, ICMP otherwise. No privilege is added (ADR 0023).
- **What gets probed.** The rules of `conflict::rules::candidate` are unchanged: only an address never leased to the client is probed, a renewal never is, and the probe cache starts empty. A renewing client whose row was lost asks for its address and gets it, because it is free (`v4/engine/mod.rs:908`). An INIT-REBOOT client (one restarting with a remembered address) without a row gets no answer (`:904-906`) and falls back to DISCOVER.
- **DECLINE.** DHCPDECLINE is honored as today, abandoning the address for the hold time with the per-client limit of 3 per hour (`Conflicts::decline_allowed`, dhcp.md section 14.6). A client that finds its new address in use by RFC 5227 address conflict detection declines it once.
- **The limits, said plainly.** ICMP is often dropped by host firewalls (Windows drops echo requests by default), and ARP needs the node on the link. The probe is the first guard and the client's DECLINE the second. Neither is complete, which is why (a) keeps write-behind rare and the loss window is bounded and counted.
- **A pair (Slice 12).** A node of a pair that starts unclean takes the same window. Its lost bindings lie in its own share, which the partner never allocates outside partner-down (ADR 0025 point 4). The resync of ha-plan section 3.8 brings back whatever the partner holds. WP12.3 records this.

## 6. Tests, one per behavior

| # | Behavior | Test (new unless named) |
|---|---|---|
| T1 | `logged` fires after the group commit and before the apply. A failed group commit fires nothing | `crates/tenko-store/tests/logged_answer.rs`, with a `test-hooks` delay in `apply_entries` and a failing writer |
| T2 | A batch with a precondition or an idempotency key gets `logged` only with its commit | same file |
| T3 | Three voters: `logged` waits for the apply. A voter added under load turns it to the apply at once | same file, on the cluster harness |
| T4 | In one entry beside foreground and background batches, each logged batch gets its own signal in order | `raft/coalescer.rs` unit tests |
| T5 | **Crash test of (a): no acknowledged lease is lost.** The child prints an ACK when its ticket completes at `logged`. The apply delay hook makes nearly every kill land between the flush and the apply; 20 kills, and the test reports how many landed in that gap. After each restart every ACK is in the rows at its revision or later, the table equals the rows, and no address went to two clients | `crates/tenko-dhcp/tests/lease_crash.rs` (extended), `bench/phase3-dhcp/scripts/crash-test.sh` |
| T6 | Two changes of one address in quick succession land in order. A second client's REQUEST for an address answered but not yet applied is refused by `HeldByOther` | `tests/lease_store.rs` (extended, with the apply delay) |
| T7 | `derived().flush()` after a completion covers that change's history row | `tests/lease_store.rs` |
| T8 | A store slower than `ack_wait`: the answer leaves at the bound, it is counted, another client's DISCOVER is not offered the address, the finding is raised and then cleared, and the row lands | `tests/lease_write_behind.rs` (a delaying store wrapper) |
| T9 | Slots or the queue full: the answer leaves at the hand-off up to the second capacity, and beyond it the request is dropped as `queue`; no allocation on that path | same file; `tests/lease_alloc.rs` (extended) |
| T10 | A change written behind and then refused: counted as lost, its address held, the marker kept at the stop | same file |
| T11 | The marker: a clean stop removes it, a kill leaves it, a start finds it, and its content is never read | `lease/recovery.rs` unit tests |
| T12 | **Crash test of (b): the probe is on after an unclean restart.** The log writer is stalled by a `test-hooks` file, the load writes behind, the child is killed and restarted. After the restart: the finding and the audit record are present; `Conflicts::effective()` is true under the Lab profile with the setting off; the lost ACKs are at most the counted ones written behind, and every other ACK is present; a free address's OFFER is probed; a fake probe that answers for a lost lease's address makes the allocator move on, so no address goes to two clients | `tests/lease_crash.rs` (a second mode) |
| T13 | The window ends after the longest lease time; DECLINE is honored inside it | `tests/conflict.rs` (extended, with the test clock) |
| T14 | Through the binary: a killed `tenko serve` comes back with `dhcp.lease.unclean_restart` and the probe line in the log | `crates/tenko/tests/acceptance_dhcp.rs` |

The existing `lease_refusal.rs`, `lease_write_cost.rs` and `acceptance_dhcp_exit.rs` must stay green. The texts "did not commit within" and `commit_wait` are swept (CONTRIBUTING's sweep rule).

## 7. Measurements: before and after, on the shipped binary

Each run is on the musl release build of `deploy/Dockerfile`, on the two lab VMs (`bench/phase3-dhcp/scripts/run-perfdhcp.sh`, phase-3-exit section 6.1). Before and after are two builds of adjacent commits, and each run names its binary. The workstation guard (`guard.sh`) is a regression check only.

| # | What | Before (LF0) | After | Expected |
|---|---|---|---|---|
| L1 | M31 again: perfdhcp with option 81 on the VMs, and the Windows stand-in on a quiet machine | today's `main` | (not changed by this plan) | A new baseline for the DDNS work; the 2026-10-22 figures are superseded |
| L2 | M26 ceiling and M28 p50 and p99 from REQUEST to ACK at 1,000, 5,000 and 10,000/s, with the commit histogram | the base build with LF1's spans | after LF2 (LF3) | At 1,000/s the commit average falls from 3.27 ms towards the fsync plus one hand-off (about 1 ms) and the p99 from 23.0 ms to single digits; at 5,000/s the p99 falls below 100 ms; the ceiling is unchanged (apply-bound) |
| L3 | Where a commit's time goes: spans from the enqueue to `client_write_ff`, from the append to the flush, from the flush to the apply's end, from the apply's end to the wake | base | LF3 | The flush-to-apply and checkpoint shares leave the ACK path |
| L4 | `strace -f -e fsync,fdatasync` of one run: fsyncs per redb durable commit | base | LF3 | Unchanged: (a) adds no write |
| L5 | M32: 20 kills on the workstation (T5) and the owner's five power-offs | (2026-10-22) | LF3 | 0 acknowledged leases lost |
| L6 | Write-behind under a slow disk: the node VM's disk throttled in Proxmox to a low write rate, perfdhcp at 1,000/s, then a kill | after LF2 | after LF4 (LF5) | Before: drops at the 2 s wait. After: the answer p99 at or below `ack_wait`, no drops up to the second capacity, the finding and the audit records, and after the kill the probe window |

The lab node VM is the lead's to set up under the lab mandate. The throttle is set on that VM only and removed after the run.

## 8. Work packages

| Package | Owner | Files | Depends on |
|---|---|---|---|
| LF0 Measure first | lab measurement | `bench/phase3-dhcp/results/<date>-m31-ddns.md` (supersedes 2026-10-22), `<date>-lease-flush-before.md` | none (L2 to L4 after LF1's spans commit) |
| LF1 Answer at the log record (store) | store builder | `crates/tenko-store/src/api.rs` (trait method with default), `raft/coalescer.rs`, `raft/log.rs`, `raft/types.rs`, `raft/mod.rs` (`propose_class`, the voter check, spans), `raft/sm.rs` (the `test-hooks` apply delay), `tests/logged_answer.rs`, `CHANGELOG.md` | none |
| LF2 The DHCP answer at the log record | DHCP builder | `crates/tenko-dhcp/src/lease/commit.rs`, `v6/lease/commit.rs`, `store.rs` (`Answered`), `lease/derived.rs` (`flush`), `server/mod.rs:1052` and `v6/server.rs:710` (read only `is_err`, kept), `tests/lease_crash.rs`, `tests/lease_store.rs`, `bench/phase3-dhcp/scripts/crash-test.sh`, `docs/dhcp.md` sections 8.2 and 8.7, `CHANGELOG.md` | LF1 |
| LF3 Measure (a) | lab measurement | `bench/phase3-dhcp/results/<date>-lease-flush-after.md`, the M32 file for the kills | LF2 |
| LF4 Write-behind and the unclean restart | DHCP builder | `lease/commit.rs` (`ack_wait`, `submit_behind`), `v6/lease/commit.rs`, `server/mod.rs` (`hand_off`, `commit_loop`), `v6/server.rs`, `lease/offer.rs` (the hold until the lease's end, sizing), `lease/metrics.rs`, `role.rs` (findings, audit), new `lease/recovery.rs`, `conflict/mod.rs` (the window), `conflict/scan.rs` (`choose`), `crates/tenko/src/serve/dhcp.rs` (marker, `choose`), `log.rs`'s stall hook (asked of LF1's owner), `ui/i18n/en.d/labels.xlf` and `sv.d/labels.xlf`, `tests/lease_write_behind.rs`, `tests/lease_alloc.rs`, `tests/lease_crash.rs`, `tests/conflict.rs`, `crates/tenko/tests/acceptance_dhcp.rs`, `docs/dhcp.md` sections 8.1, 8.6, 10.6 and 14.5, `docs/dhcp-contracts.md` section 8, `CHANGELOG.md` | LF2, LF3 (the bound), LF-Q1 to LF-Q7 |
| LF5 Measure (b), then the documents | lab measurement, then the lead | `bench/phase3-dhcp/results/<date>-write-behind.md`; after the owner's word on section 9: a new ADR 0039 (proposed 0039; 0036 and 0037 are claimed by the notifications and discovery plans, 0038 by the takeover script), `docs/REQUIREMENTS.md` (DHCP-07), `docs/plans/phase-3-exit.md` (E24, M32 note), ADR 0019 and ADR 0030 status lines, `docs/plans/ha-plan.md` section 3.1 (one sentence), the requirement trace | LF4 |

LF1 and LF2 can merge as one gate run. LF4 waits for LF3, because the bound is set from L2. None of the packages changes a stored format: `seq` is skipped by serde, and the marker is a file without content. `deploy/`, the installer and the API need no change. The new findings and metrics reach `ui/` only through the existing generic health view and the label catalog.

## 9. The documents: proposed text for the owner

These are proposals, marked so in the files until the owner accepts them. They land in LF5, after the measurement.

**DHCP-07, proposed:** "Durable lease store on each node that serves a scope, with lease history. A lease is answered once its record is durable in the serving node's log, which is group-committed (one flush per group), not after the store has applied it. While that log lags past a bound, the answer may precede the write, by at most that bound in time and a bounded number of changes. The node counts and shows this, and after an unclean restart it probes every new address and honors DHCPDECLINE until every lease that could have been lost has ended. Leases are published to the controllers' store after the answer and never pass through the global Raft group on the DORA path."

**E24, proposed:** "Leases survive the node: the node is killed (SIGKILL, and a power-off of the lab VM) under perfdhcp load and restarted. No lease answered at its log record is lost. Leases answered ahead of their write while the log lagged are counted, a kill loses at most those, and the restart turns the conflict probe on for new addresses. No address is leased to two clients while the probe answers, and the role's lease table equals the store's rows. While the store refuses writes (the test hook of WP6.2) the role behaves as P3-Q14 decides." The kills of 2026-10-22 remain evidence for the first sentence. T5, T12 and L5 add the rest.

**ADR 0019 point 3, proposed amendment** (through the new ADR 0039, "When the lease answer leaves", which also amends ADR 0030 points 1 and 9):
- "The ACK or REPLY leaves when the batch's log entry is durable on the serving node. On a single voter that entry is committed and its apply cannot refuse it. With more than one voter it leaves when the batch is applied."
- "While the commit path lags past the answer bound (500 ms), the answer leaves at the bound and the change is written behind it. The address stays held for the client, and the count is bounded and shown."
- "An unclean restart turns conflict probing on for new addresses for the longest lease time."
- "Renewals are written like new leases. One written behind can be lost by a crash, and the probe and DHCPDECLINE recover from that."
- ADR 0019's sentence "a renewal that is not durable can let the address be given to another client after a crash" is kept as the reason for the probe.

## 10. Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| LF-Q1 | Write-behind in every profile with no setting, or off under Hardened? | **On everywhere, no setting.** Your rule is "never", (a) makes it rare, and it is always shown and audited. A Hardened site that prefers a dropped request to a counted risk is the alternative, as a profile column |
| LF-Q2 | The answer bound: a constant of 500 ms, confirmed or replaced by LF3's measurement? | **Yes, a constant.** It is not an operator's choice: it follows from the client's retransmission and the measured tail |
| LF-Q3 | How much may be answered ahead of its write: one hand-off queue's worth again (256 to 4,096, plus 512 in flight)? | **Yes.** It is the loss window. A disk stalled for longer is a failure to show (`dhcp.lease.write_behind` says so), not to hide behind more memory |
| LF-Q4 | Probe after every unclean restart, or only after one during write-behind? | **Every unclean restart.** It also covers disks and hypervisors that lie about flushes. Knowing that write-behind ran would need a durable write at the very moment the disk is slow. The cost is the probe's wait (at most 300 ms) on the first offer of each new address during the window |
| LF-Q5 | The window: the longest lease time of the served scopes (8 days for an imported Windows default), half of it (T1), or one hour? | **The longest lease time.** A client whose lease was lost and that cannot renew keeps using the address until its end. The probe costs little per new address |
| LF-Q6 | During the window, the probe overrides `conflict_detection = off` and the Lab profile, and runs without the `probe` role (the `dhcp` role builds the same `ScanProbe`)? | **Yes to all three.** It uses only what the service holds; no privilege changes (ADR 0023) |
| LF-Q7 | A store that refuses writes (a disk error, a quorum loss): keep P3-Q14 (renewals answered for their remaining time, new clients dropped), or write behind into it too? | **Keep P3-Q14.** Write-behind into a store that refuses grows without end and promises leases that never land. Slice 12's node store removes the quorum case |
| LF-Q8 | The document changes of section 9 as a new ADR 0039 plus the DHCP-07 and E24 texts, written after LF3 and LF5? | **Yes.** The texts follow what was measured, not what was expected |
