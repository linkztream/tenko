# Lease flush plan: storage never keeps a client from its lease

- Status: Accepted. The direction is the owner's decision of 2026-11-21 (F94, option A1), and the owner answered every open point of section 10 (LF-Q1 to LF-Q9) as recommended on the same day. He added one demand: the operator manual states the worst case of write-behind (8,704 leases lost at the cap), why that is the bound, and the reasoning behind the decision, namely that a client getting its lease weighs more than the lease being on disk at the moment of a crash, with the protections that follow (LF4, `docs/dhcp.md`).
- Date: 2026-11-21
- Scope: when the DHCP answer (DHCPACK, and REPLY for DHCPv6) leaves relative to the lease's write. (a) Normal mode: the answer waits for the lease's log record to be committed, which is group-committed and on one voter is the local flush, and no longer for the apply behind it. (b) Write-behind, DHCPv4 only: while the log lags past a bound, the answer leaves from memory, the write follows, the node says so, and after an unclean restart the conflict probe is on for new addresses and DHCPDECLINE is honored. Written against `main` at `75af2f27`. Sources: [ADR 0019](../adr/0019-dhcp-data-model-and-lease-path.md) point 3, [ADR 0030](../adr/0030-durability-classes-of-the-lease-path.md) (its "next step" 2 is design (a)), [ADR 0025](../adr/0025-dhcp-failover-and-data-plane-ha.md) and [ha-plan.md](ha-plan.md) section 3.1 (Slice 12: the node store), DHCP-07 in [REQUIREMENTS.md](../REQUIREMENTS.md), E24 and M26 to M32 in [phase-3-exit.md](phase-3-exit.md), [dhcp.md](../dhcp.md) sections 8 and 14; openraft 0.9.25 as pinned in `Cargo.lock`.

## 1. The problem, with the figures we have

Today the answer waits for the whole store pipeline, not only for the disk. A change goes from the worker to the hand-off queue, the committer, the coalescer, openraft, the log writer's group commit (one redb transaction with `Durability::Immediate`, one fsync per group), openraft's commit, the apply on a blocking thread (with the derived index's `absorb`), the coalescer's answer task, and back through the committer to the worker. Only the fsync makes the lease durable: the state machine applies with `Durability::None` and is made durable by a checkpoint once a second (ADR 0030 point 9). Everything after the commit adds latency and no durability.

| Figure | Value | Where and when |
|---|---|---|
| Commit average, one worker, two VMs, final build 0.0.10 | 3.27 and 3.01 ms at 1,000/s; 9.22 and 10.05 ms at 5,000/s; 28.89 and 29.27 ms at 10,000/s; 163 and 159 ms at 15,000/s | `bench/phase3-dhcp/results/2026-10-30-e22-real-link.md` (2026-10-30) |
| The same node's fsync | idle probe p50 0.3 ms, p99 0.6 to 1.1 ms; the disk does 1,230 to 1,340 synchronous 4 KiB writes per second | same file |
| REQUEST to ACK (M28) | p50 3.02 ms, p99 23.0 ms at 1,000/s; p99 110 ms at 5,000/s; the commit almost all of it | same file; phase-3-exit M28 |
| Ceiling (M26) | 9,995 exchanges/s within 0.1 percent drops; bounded by about 65,000 rows/s applied (ADR 0031) | same file |
| The commit tail on the workstation | 87 to 98 percent of commits above 25 ms waited behind the once-a-second `sm.redb` checkpoint (stalls of 25 to 75 ms) | ADR 0030, "The tail that remains" (2026-10-30) |
| M31, DDNS end to end | names p99 699 and 777 ms, DORA p99 403 and 430 ms (stand-in, Windows, loopback) | `2026-10-22-m31-ddns.md` (2026-10-22 and 23) |
| M32, kills under load | 20 kills, 144,681 ACKs, none lost | `2026-10-22-m32-crash.md` (2026-10-22) |

So at 1,000/s about 90 percent of the commit is pipeline (3.27 ms against an fsync p50 of 0.3 ms). M31 is older than the store it blames: it was measured before WP9.6 and WP9.7 (ADR 0030 and ADR 0031), when a lease commit was 13 rows and 3.7 KB and a snapshot fired every few hundred entries. Today a lease commit is 2 rows and about 670 bytes. M31 is therefore measured again on today's `main` before anything here is built (LF0); its result decides nothing in this plan and is the baseline for the DDNS work.

Storage refuses a client today in four places:

1. the worker's pending slots are full: `crates/tenko-dhcp/src/server/mod.rs:974-977` (`DropReason::Queue`);
2. the hand-off queue is full: `lease/commit.rs:291-292` returns `SubmitError::Full`, `server/mod.rs:999-1001` drops;
3. the change has not committed within `commit_wait` (2 s): `lease/commit.rs:539-552` fails the ticket, the worker drops;
4. the store refuses writes: the refusal gate (`lease/refusal.rs`, P3-Q14).

A fifth, `HeldByOther` in `lease/batch.rs:142-144`, is correctness and stays. Design (a) removes most of the latency that leads to 1 to 3. Design (b) removes 1 to 3 as reasons to stay silent while the store is only slow, for DHCPv4. Point 4 stays (LF-Q7).

The owner's note on writes: small separate writes each cost whole filesystem blocks. Both designs keep one durable write per group and add none per lease; section 2.5 rejects a second lease journal for the same reason.

## 2. Design (a): the answer waits for the commit of the log record, not the apply

### 2.1 What changes in the store

The store gets one call beside `propose` in the `Store` trait (`crates/tenko-store/src/api.rs:1231-1251`):

`propose_logged(batch, logged: oneshot::Sender<()>) -> Result<Committed, StoreError>`

It is `propose`, and it also fires `logged` once the batch can no longer be lost or refused. The default implementation, which `MemStore` uses, fires `logged` with the commit, so every store other than the Raft store keeps today's behavior. The Raft store fires it at openraft's commit of the entry when the batch cannot fail at apply: no preconditions, no idempotency key, and `validate` passed at propose (`raft/mod.rs:2086`). A lease batch is such a batch (`lease/batch.rs:135-179` adds neither). Every other batch gets `logged` only with an `Ok` result, never with an error.

The signal is openraft's own. `Command::Commit` calls the log store's `save_committed(upto)` and only then applies (openraft 0.9.25, `raft_core.rs:1694-1700`). It is emitted only for entries a quorum accepted in the leader's term (`replication_handler/mod.rs:223-241`). On one voter it runs right after the leader's own flush, in the same core loop. `save_committed` is ours (`raft/log.rs:713-722`). This is the exact Raft commit on any number of voters: no voter check, no read of `raft.metrics()`.

How the commit reaches the batch:
- `Queued` (`raft/coalescer.rs:48-53`) gains `logged: Option<oneshot::Sender<()>>`.
- `Proposal` (`raft/types.rs:62-72`) gains `#[serde(skip)] seq: u64`, which the coalescer sets for each entry it hands to `client_write_ff` (`coalescer.rs:220`). It counts from 1, and 0 means none, so an entry another leader wrote (read as 0) never fires anything. This node's own earlier entries that a new leader keeps fire on the follower path (`following_handler/mod.rs:157-176`, also `Command::Commit`), which is right: they are committed. `Proposal`'s `PartialEq` leaves `seq` out (written by hand), so a read-back entry equals the written one. Being skipped by serde, it changes neither the log nor the wire format, and `deny_unknown_fields` is not touched.
- Before `client_write_ff`, the coalescer moves the entry's `logged` senders into a map shared with the log store, keyed by `seq`.
- openraft passes the leader's own entries to `append` unencoded (`write_entry`, `raft_core.rs:488`, through `leader_append_entries` and `Command::AppendInputEntries` to `log_store.append`). So `append` (`log.rs:739-768`) records `index -> seq` for each entry with a `seq`.
- `save_committed` fires the senders of every `seq` whose index is at or below `upto` and removes them. It stays a memory write, as today.
- `truncate` (`log.rs:770`) drops the senders of the entries it removes, unfired. An entry that a new leader replaces can therefore never fire `logged`, whatever this node commits later. Firing per entry, not through a "highest committed" watch, is what makes that exact.
- `purge` drops the map's entries at or below its index, because a follower's snapshot install sets the commit without `save_committed` (`following_handler/mod.rs:315-325`). The `client_write_ff` error path (`coalescer.rs:221-226`) takes its senders out of the map before it answers. The map therefore holds at most the four entries in flight per leadership episode.
- `answer` (`coalescer.rs:232`) awaits the response and sends each `Committed` as today. A sender still in the map when the response arrives (a store without this path, or an error) is dropped unfired.

What stays: the coalescer's four entries in flight (`max_inflight_entries`) are still released at the answer, that is after the apply. Entries committed but not applied therefore stay bounded at 4 × 128 batches, and an apply that falls behind still slows new answers. (a) moves latency. It does not raise the ceiling, which the apply rate sets (M26).

### 2.2 What changes in the DHCP committer

In `Running::start` (`lease/commit.rs:510-600`, and the same in `v6/lease/commit.rs:454-530`), `store.propose(batch)` (`:544`) becomes `propose_logged`. When `logged` fires, the ticket completes and the worker sends the ACK. Everything else stays at the commit result, as today:
- the row goes into the role's table at the commit's revision (`:565`);
- the derived history row is pushed (`:571-578`);
- `gate.committed()` is called;
- the address and the client stay in the committer's busy set (`:473`).

The `Completion` outcome (`crates/tenko-dhcp/src/store.rs:58-63`) becomes `Result<Answered, CommitError>`, where `Answered` is `Committed(Revision)`, `Logged` or `Behind` (section 3). The two servers read only `is_err` (`server/mod.rs:1052`, `v6/server.rs:710`). The server's own apply of the row at completion (`server/mod.rs:1053-1057`, for a table that does not apply commits) runs only for `Committed`: only `StoreLeases`, whose table applies commits, ever answers `Logged` or `Behind`.

**A dropped `logged` sender means "wait for the result", never "answered".** The receiver can close unfired (a truncated entry, the `client_write_ff` error path, a batch forwarded after `NotLeader`). The committer then completes nothing at that moment and waits for `propose`'s result, as today: an `Ok` answers, an error fails the ticket.

**An error after `logged`.** If `propose` then returns an error (`Timeout` after `write_timeout`, 60 s, `raft/mod.rs:1788`, or `ShuttingDown`), the entry is committed and will apply: the feed brings it. The committer treats it as "answered, outcome unknown":
- there is no second completion, and no `gate.refused`, since it is not a refusal;
- the keys stay busy and the address hold of section 2.3 stays until the feed shows the row. "Shows the row" means the table holds a row at the change's `(vrf, addr)` with a `cltt` at or above the change's;
- at the stop token that wait ends: the change is counted as unknown, and the clean-close marker is kept (section 5.1);
- it is counted and logged.

**Why the table is not filled at the commit.** A row applied at `Revision::ZERO` is ordered against the feed's copies by `cltt` alone (`lease/table.rs:251-258`), and a DDNS outcome rewrites the lease row with the same `cltt` (`ddns/worker.rs:922-965`). A tie could put an older row over a newer one. Leaving the table to the commit result keeps one ordering rule; the window between the ACK and the table is closed by the hold of section 2.3.

`StoreLeases::derived().flush()` (`lease/derived.rs:301`) first waits until each answered change has applied or been counted lost or unknown, so that a flush after a completion still covers its history row (ADR 0030 point 2; the operator's release and the tests rely on it). The 2 s `commit_wait` stays until (b) replaces it for DHCPv4 (section 3.2) and stays for DHCPv6, now measuring the time to the commit.

### 2.3 The hold, counted per change

What guards an address today:
- **The guards.** The allocator's guards are the table and the offer hold (`allocator.rs:152-175`). The v4 server's offer hold is the engine's `v4::engine::offers::OfferTable` (`server/mod.rs:344`, made at `:492`). The engine holds it for every DISCOVER (`v4/engine/mod.rs:776-780`) and for every writing REQUEST (`:988-993`), each for `offer_secs` (10 s). `server/mod.rs:1209` is the conflict mark, which ends the client's offer at once.
- **What the table cannot carry.** The table has one slot per address. A new hold by the same client overwrites `until` (`offers.rs:284-290`). There is no release. When a probe window is full, the live slot that ends first is evicted, and `hold` still returns true (`:250-291`; module notes `:10-13`).
- **The case that breaks.** A REQUEST is therefore guarded for 10 s today. A stall longer than that, or a DISCOVER of the same client that lowers `until`, leaves only `HeldByOther` at build, which under (b) runs after the answer.

The fix is in `v4/engine/offers.rs`, at the hold the engine already takes; there is no second hold at the hand-off.

**The slot rule.**
- **Held means counted.** Each slot gains a count of the changes that hold it (a `u16` beside `who`). A slot is held while its count is above zero, whatever its `until` says.
- **`until` keeps its offer meaning.** The hold at `:990` stays at `offer_secs`. A slot at zero is held while `until` is in the future, as today, so offers and the conflict mark (`server/mod.rs:1209`) work as they do now.
- **Taken at `:990`.** The writing REQUEST's hold counts up. The count uses `checked_add`, and at its maximum the hold refuses as `Full`.
- **Same client.** A hold by the client the slot names keeps the count, so its DISCOVER at `:778` and the conflict mark change only `until`.
- **Another client** can hold the slot only when the count is zero, and that hold resets the count.
- **Releasing.** A new `OfferTable::release(scope, addr, identity)` checks that `who` is that client and counts down. The slot then stays `used` even at zero, so that the duplicate-clearing walk in `hold` (`offers.rs:273-283`) never tombstones a counted copy further on in the window.
- **Never evicted.** A counted slot is never evicted. The eviction candidate starts unset (today `oldest = start`, `offers.rs:250`) and only zero-count slots can become it. `grow` never overwrites a counted slot; where its placement would (`offers.rs:151-161`), it keeps that stripe at its old size instead.
- **DECLINE.** `decline` (`v4/engine/mod.rs:1174-1180`) accepts the client a counted slot names as a holder, as RELEASE does below, so a DECLINE answered behind is not ignored as `NotHolder`.

**Three answers.** `hold` returns `Held | Other | Full`:
- `Other`: another client holds the address (two workers racing for A). It behaves as today: `:990` refuses with a NAK, `:778` continues.
- `Full`: no zero-count slot is free in the window, or the count is at its maximum. It drops the request as `Queue` on both paths. At `:778` this replaces today's re-run of `allocate`, which would pick the same address again and end in a mislabeled `Drop(PoolFull)` (`mod.rs:806`).

**No exemption.** The hold is counted for every DHCPv4 change that binds an address, renewals included. An exemption for a row already bound to the client lets two clients through under a stall: X releases A and asks for it again (Windows `/release` then `/renew`), or its row expires while its renewal waits, or an operator releases it. The release applies, A is free and unheld, Y takes A and is answered behind, and two clients hold one address.

**Each change counts down exactly once.** `StoreLeases` gets the server's offer table to call `release`, and it calls it once per change, at the first of these:
- **An answered change** (`Logged`, `Behind`, or an error after `logged`): when the row has applied, or when the feed shows it.
- **A lost change** (answered behind, then refused or not written by a stop): at the moment it is counted lost. That release also raises `until` to the lost lease's end, which keeps the address from other clients until then, as 3.2 item 4 says.
- **A change that did not answer the client**, at once:
  - a build error (`HeldByOther`, `Encode`; `commit.rs:528-540`);
  - a refusal before the answer (`:585-595`);
  - a failed `submit` (`server/mod.rs:994-1003`);
  - the timer's failed pop on a store that is not a sole voter (section 3.2 item 1);
  - a stop that fails the change (`commit.rs:444-460`);
  - the path that leaves the engine after `:990` without a hand-off (`reply` returning `Drop(Malformed)`, `v4/engine/mod.rs:1018-1029`).

Because the release counts down, an unanswered change of X never clears the hold that X's earlier answered change still needs. A change the timer already failed and released is not released again when its commit lands.

**Bounds and cost.** Per key the count is at most the changes in the committer (8,704, the FIFO capping at 8,192 per `ack_wait`) plus the workers between `:990` and the hand-off, far below 65,535. The counted slots alive at once are bounded by the same figure, and the offer table is sized from the image with room for them (dhcp.md section 10.8). One slot operation without allocation per change. It covers (a)'s window between the ACK and the apply, and every change of (b).

**This is proven in code, not in prose:** T20 (section 6) is a property test of the table and the change lifecycle, written before the code, and it is the gate of LF4.

A DHCPRELEASE inside that window is today ignored as `NotHolder` (`v4/engine/mod.rs:1218-1223`), so the lease would stay bound to its end. The engine accepts a RELEASE from the client a counted slot names, and the change goes through the busy set after the first. DHCPv6 takes no hold in this plan: it is never written behind, so its gap is (a)'s few milliseconds. Its engine keeps today's holder check, and a RELEASE in that gap is ignored and counted as `NotHolder`, as today; the lease then ends at its time.

### 2.4 Why (a) is safe

1. **The signal is the commit.** `save_committed` covers only entries a quorum accepted in the leader's term; with one voter its own flush is that quorum. A committed entry is never truncated (Raft's leader completeness).
2. **The apply cannot refuse it.** The apply is deterministic. A lease batch has no precondition and no idempotency key, and its size was validated at propose. An error inside the apply stops the store (`sm.rs:475-540`, `stopped_at`), the same failure as a dead disk, and the next start replays the entry from the log.
3. **A start applies every committed entry before the role reads.** The state machine replays the log from its last checkpoint (ADR 0030 point 9). A sole voter's start waits for "leader with the log applied" (`raft/mod.rs:1615-1625`) before the role rebuilds its table. The crash test of section 6 proves it with kills between the commit and the apply.
4. **The durability is today's.** Today's ACK waits for this commit and then for an apply that writes nothing durable. (a) removes the wait for the apply and adds no new loss window.
5. **No new window for two clients.** The table, the busy set and `HeldByOther` move at the same moment as today; only the ACK leaves earlier, and the hold of section 2.3 covers the client's own follow-up.

### 2.5 More than one voter, the Slice 12 node store, and what was rejected

- **A controllers' group of more than one voter.** (a) holds there too: the answer waits for the quorum's commit, one round trip to the followers, no longer for the apply. The `dhcp` role on a controller of a multi-voter cluster still has a quorum on the DORA path, which CONTRIBUTING rule 5 forbids (ADR 0025, Context). Slice 12 removes that, not this plan. Write-behind (section 3) does not run on such a group.
- **The node store (ha-plan section 3.1, WP12.2).** It is a one-voter instance of `tenko-store`, never a member of the controllers' group. (a) lives in `tenko-store`, so the node store answers leases at its flush with no further work, on a controller node and on a data-plane node alike. The publication to the controllers' store (ha-plan section 3.9) is batched (every 100 ms or 1,000 rows) after the answer, so a lease still costs one grouped fsync before the ACK.
- **A pair (WP12.3).** A binding update goes to the partner after the local commit, in revision order (ha-plan section 3.8). With (a) the answer may leave before the update is sent: HA-Q3's lazy update, bounded by the MCLT (maximum client lead time). The 50 ms wait for a new binding's acknowledgment (ADR 0025 point 5) is unchanged.
- **Rejected: a table row at `Revision::ZERO` at the commit**, for the `cltt` tie of section 2.2.
- **Rejected: a voter check at the flush.** It fires on the flush only on one voter and reads openraft's metrics, which can be stale (`sole_voter` clones them, `raft/mod.rs:1547`). `save_committed` is exact on any voter count.
- **Rejected: a separate append-only lease journal**, the full version of ADR 0019 point 4. Slice 12's node store is that journal; a third file on a controller node would add a second fsync per group, the small separate writes the owner warned of.
- **Rejected: a fixed flush period**, dhcpd's delayed ACK. It delays a lone lease at idle; the adaptive group commit already batches under load.

## 3. Design (b): write-behind while the log lags (DHCPv4)

### 3.1 The rule

A DHCPv4 change is answered no later than its answer bound after its hand-off, wherever it waits: in the queue, deferred behind a busy key, or in flight. If its record is not committed by then, the answer leaves from memory and the write follows. The same holds when there is no room to wait (no free slot, the queue at its normal capacity). There is no mode to enter and leave: each change is answered at its commit (a) or written behind (b), and the node is *writing behind* while at least one answered change is not yet committed.

Write-behind runs only while the store is a sole voter: today's single controller, and the Slice 12 node store, which is one voter by design. A controllers' group of several voters gets (a) only and keeps today's drop at the bound.
- **Why.** A lagging commit there is usually a lost quorum or a lost leadership, which does not refuse quickly (`write_timeout`, 60 s, `raft/mod.rs:1788`). Writing behind into it would answer up to the whole loss window with changes that may never land, which LF-Q7 rejects for a store that refuses.
- **How it is read.** `Store::sole_voter` (`false` by default) is not cheap on the Raft store: it clones openraft's metrics and collects the voters (`raft/mod.rs:1547-1551`). The committer therefore reads it once per wake of its loop into a cached flag (an `AtomicBool` in `StoreLeases`'s shared state), and the timer's pop and the worker's no-slot path (section 3.2) read only the flag. A stale flag is harmless here: at worst one episode starts or stops a moment late, and the hold protects the addresses either way.

DHCPv6 is not written behind in this plan, for IA_NA nor IA_PD. It keeps (a) and today's drop at `commit_wait`. The probe is IPv4 only (`rules::candidate` parses a DHCPv4 message, `ScanProbe` uses ARP and ICMPv4), and a lost delegated prefix (`v6/engine/alloc.rs:210-218`) would be delegated again with nothing to detect it: prefixes have no duplicate address detection and no DECLINE. LF-Q9 holds what v6 write-behind would need.

### 3.2 The code places

1. **One FIFO of deadlines.** `submit` pushes `(at + ack_wait, ticket)` into one FIFO. Every change holds its entry for `ack_wait`, even one answered at its commit in 3 ms, so the FIFO holds the hand-off rate times `ack_wait`. It and the answered set are made at full size up front for that at the ceiling: 16,384 changes a second (above the 11,125 the closed loop reached, M26) times 500 ms, 8,192 entries of about 24 bytes each. A full FIFO refuses the submit as `queue`, so a push never reallocates on the DORA path. A ticket that names no slot (item 2) takes a reserved slot index with a running number in its generation bits, so the answered set tells it apart from every slot ticket. The committer's loop (`lease/commit.rs:424-443`) gains a `sleep_until` arm for the FIFO's front. At each wake it pops every entry that is past due and completes it `Behind`, unless it was already answered: an answered set made at its full size up front, and `server::release` ignores a second completion through the slot's generation all the same. This covers a change wherever it waits (queued, deferred or in flight), costs O(1) per change, and replaces the deadline inside `start` (`:539-552`). When the cached sole-voter flag is false, the same pop fails the ticket instead, which is today's drop at the bound. `commit_wait` is renamed `ack_wait` and set to 500 ms (section 3.3) for DHCPv4; DHCPv6 keeps 2 s and its drop.
2. **No room is no reason to drop.** The queue is made at twice its sized capacity (`commit.rs:195`, and `grow_queue` at `:327` the same), so a push past the normal capacity never reallocates on the DORA path. In `hand_off` (`server/mod.rs:960-1005`), when no slot is free (`:974`) or the queue is at its normal capacity (`:999`), the worker first reads the cached sole-voter flag. While it is false, the request drops as `queue`, as today. While it is true, the worker submits the change with a ticket that names no slot, up to twice the capacity, and sends the reply from its scratch buffer only after that `submit` returned `Ok`. A closed gate (`Refused`) or a full FIFO drops it as today and releases the hold taken at `v4/engine/mod.rs:990`. `tests/lease_alloc.rs` covers this path. Only past twice the capacity is the request dropped as `queue`.
3. **The commit loop** (`server/mod.rs:1025-1060`) sends `Behind` answers like commits and counts them, without the server's own table apply (section 2.2). When the row lands, the committer applies it and pushes history, as for any commit; the hold is released once, by the rule of section 2.3, and not again here.
4. **The refusal gate stays** (LF-Q7). A store that refuses writes is not lagging: write-behind into it would grow without end. A change refused before its answer fails as today and releases its hold. A change written behind and then refused is counted as lost (section 4); its hold keeps the address from other clients until the lease's end, and the clean-close marker is kept (section 5).
5. **A `HeldByOther` on a change written behind** cannot happen while the counted hold of section 2.3 is in place. If it does, it is counted as lost and logged as an error, and the tests assert zero.
6. **A stop under lag.** Today a stop fails every queued change (`commit.rs:444-460`). The committer keeps proposing the answered changes until the role's stop deadline, counts the rest as lost, and fails only the unanswered ones as today, releasing their holds.

Loss window: every answered change not yet committed. That is the in-flight changes, the queue and the room beyond it: 512 + 2 × the queue's sized capacity, 8,704 changes at the largest queue (4,096). That is about 0.9 s of load at 10,000/s and 8.7 s at 1,000/s. Only answered changes keep a hold past their completion, so the holds of lost changes are bounded by the same figure, which the offer table is sized for. They stay until their lease's end while the process runs, and they are counted in the finding.

### 3.3 The bound and how it is chosen

| Bound | Proposed | How it is chosen |
|---|---|---|
| `ack_wait`, the time from the hand-off to the answer | 500 ms, a constant in `CommitSettings`, not a setting (the tunables rule) | The upper limit wins: the answer must never cause a retransmission. RFC 2131 section 4.1 has the client retransmit after about 4 s (randomized by ±1 s, so 3 s at the earliest), and RFC 8415 a DHCPv6 REQUEST after REQ_TIMEOUT 1 s with RAND ±0.1, so 0.9 s at the earliest. The bound stays below 0.9 s, so that v6 can share it if LF-Q9 adds v6. The lower limit is measured at the target rate, not at the ceiling: at 5,000/s after (a) (LF3), the bound is at least ten times the p99.9 from the hand-off to the answer. At the ceiling the commit average is 29 ms at 10,000/s and 163 ms at 15,000/s (2026-10-30), so a lower limit taken there could pass 1 s; there write-behind is the right answer. LF3 confirms 500 ms or names the figure |
| The room beyond the queue, the changes that may be written behind | The queue's own sized capacity again (dhcp.md section 10.8: 256 to 4,096), about 6.6 MiB at the cap | It is part of the loss window of an unclean stop, sized with the rule that already sizes the queue: one fact in one place, no new setting. Beyond it a stalled disk is a failure to show, not to hide (LF-Q3) |

## 4. What the operator sees

| Kind | Name | When |
|---|---|---|
| Histogram | `tenko_dhcp_commit_duration_seconds` (kept, same meaning) | From the hand-off to the commit's result |
| Histogram | `tenko_dhcp_answer_duration_seconds{family}` (new) | From the hand-off to the answer: the commit, or the bound |
| Counter | `tenko_dhcp_write_behind_total` | An answer left before its write |
| Gauge | `tenko_dhcp_write_behind_pending` | Answered changes not yet committed |
| Counter | `tenko_dhcp_write_behind_lost_total` | A change written behind that the store refused, that a stop could not write, or a `HeldByOther` |
| Counter | `tenko_dhcp_commit_unknown_total{family}` | An error after `logged` (section 2.2) |
| Health finding, warning | `dhcp.lease.write_behind` | Raised at the first answer written behind, with the time, the count and the most pending; cleared when nothing is pending. Says: "The disk is slower than the clients: N leases were answered before they were written; a crash now would lose at most M." |
| Health finding, error | `dhcp.lease.write_behind_lost` | A change written behind was lost; names the addresses held for it. It stays until the next start, which probes |
| Health finding, warning | `dhcp.lease.unclean_restart` | The start found the marker (section 5). Says until when new addresses are probed and with which method, or, as an error, that no probe can run on this node |
| Audit | `dhcp.lease.write_behind` | One record per episode (from the first pending to none pending): the start, the end, the count, the most pending, the lost |
| Audit | `dhcp.lease.recovery` | An unclean start: the window's end and the probe method |
| Log | warning lines | The start and end of an episode, an unclean start, an error after `logged` |

On a controllers' group of several voters there is no write-behind and none of its findings. A commit that misses the bound drops the request as today (`tenko_dhcp_dropped_total{reason="store_refused"}`), and `docs/dhcp.md` section 8.6 says why: a lagging quorum is not a slow disk.

The audit actions need English and Swedish labels in `ui/i18n/<language>.d/labels.xlf` (the label catalog test). The findings use the existing health row display, and the notification rules can route them like any finding.

## 5. The unclean restart: the marker and the probe

### 5.1 The clean-close marker

- **The file.** `<data_dir>/dhcp.open`, named in one place: a new `crates/tenko-dhcp/src/lease/recovery.rs`. It is written with `tenko_store::fs::write_private` (temporary file, fsync, rename, directory sync) before the role binds its first listener, so it is durable before the first answer.
- **Removal at a clean stop.** The file is removed only when all of these hold:
  - the listeners are closed and the queue has drained;
  - every answered change has committed and the derived writer has flushed;
  - `write_behind_lost` is zero;
  - no probe window is open.

  A stop inside an open window keeps the file, so the next start opens a fresh window. That window is at least as long, and therefore safe, and the file's content is still never read. The window ends for good only when the node has run through its end.
- **The next start.** A start that finds the file is unclean.
- **Never parsed.** Its existence is the whole signal: anyone able to write it can only turn probing on, and anyone able to write `<data_dir>` already holds the store (ADR 0023's threat model is unchanged).
- **A restore** (`copy_closed_store`, `tenko-store/src/format.rs:304`, through `crates/tenko/src/backup/`) starts an older state. The restore step writes the marker into the restored data directory, so the first start after a restore probes. This gap predates the plan and is closed here because the marker exists.
- **Fail-safe edges.** A backup that copied a running node's marker only causes an extra window. The first start after the upgrade finds no file, which is right: the old binary never answered ahead of the write.

### 5.2 The probe after an unclean start

- **What it covers.** Every start that finds the marker, not only one after write-behind (LF-Q4). That includes a disk or hypervisor that acknowledged a flush it did not make, as long as the marker itself survived. With `cache=unsafe` the marker's removal can reach the disk while the log does not, and then nothing protects the start: the plan claims only the starts that find the marker.
- **How long.** From the start until the latest of two times (LF-Q5): the start plus the longest grant the first configuration image allows (the scopes' times, the lease-time actions of policies and classes, the reservations' overrides), and the latest `ends` among the rows of the rebuilt table. The rows carry the times of the image the lost grants were made under, so a time lowered since the crash does not shorten the window. By its end every lease a crash could have lost has ended or been renewed.
- **What it forces on.**
  - The window is a field of `ConflictSettings` (`conflict/mod.rs:157-198`). `Conflicts::effective` (`:320-327`) answers true until it ends, whatever `dhcp.settings.conflict_detection` and the profile say (LF-Q6).
  - The probe is the same `ScanProbe` without the `probe` role: `scan::choose` (`scan.rs:105`) takes `probe_role || unclean`, called from `crates/tenko/src/serve/dhcp.rs:363`. It uses what the service already holds: ARP with `CAP_NET_RAW` on the link, ICMP otherwise. No privilege is added (ADR 0023).
- **What gets probed.** Inside the window, the holder rules of `conflict::rules::candidate` (`rules.rs:125-136`) skip the probe only for a row still *bound* to this client: active and not past its end. Outside the window they are unchanged. Without this, the most common lost case is missed: Y's expired row on A survives, X's grant of A was written behind and lost, and Y's DISCOVER for A would be offered A unprobed while X uses it. A renewing client whose row was lost asks for its address and gets it, because it is free (`v4/engine/mod.rs:908`). An INIT-REBOOT client (one restarting with a remembered address) without a row gets no answer (`:904-906`) and falls back to DISCOVER.
- **A full probe table.** Inside the window, an OFFER that cannot be parked for a probe (`Conflicts::park`, `conflict/mod.rs:395-405`, 1,024 slots) is dropped instead of sent unprobed. The client retransmits, which is what a site-wide power loss produces above about 3,400 new offers a second.
- **DECLINE.** DHCPDECLINE is honored as today: the address is abandoned for the hold time, with the per-client limit of 3 per hour (`Conflicts::decline_allowed`, dhcp.md section 14.6). A client that finds its new address in use by RFC 5227 address conflict detection declines it once.
- **The limits, said plainly.** ICMP is often dropped by host firewalls (Windows drops echo requests by default), and ARP needs the node on the link. The probe is the first guard and the client's DECLINE the second. Neither is complete, which is why (a) keeps write-behind rare and the loss window is bounded and counted.
- **A pair (Slice 12).** A node of a pair that starts unclean takes the same window. Its lost bindings lie in its own share, which the partner never allocates outside partner-down (ADR 0025 point 4). The resync of ha-plan section 3.8 brings back whatever the partner holds. WP12.3 records this.

## 6. Tests, one per behavior

Each test must fail on today's code, with three exceptions. T5's no-loss assertion is met by today's code too; T5 adds the share of kills in the gap. T7 and T17 are regression guards: they pass today and must keep passing.

| # | Behavior | Test (new unless named) |
|---|---|---|
| T1 | `logged` fires at `save_committed` and before the apply (the apply delay hook holds it). A failed group commit fires nothing. Entries another leader wrote (`seq` 0) fire nothing. `purge` and a snapshot install leave no map entry behind | `crates/tenko-store/tests/logged_answer.rs`, with a `test-hooks` delay in `apply_entries` and a failing writer |
| T2 | A batch with a precondition or an idempotency key gets `logged` only with its result | same file |
| T3 | Three voters: `logged` fires at the quorum's commit, before the apply. A leader that loses its leadership before the commit fires nothing for its truncated entries, also after it leads again. A former leader's entry that the new leader keeps fires on the follower path. A non-lease batch fires only on `Ok` | same file, on the cluster harness |
| T4 | In one entry beside foreground and background batches, each logged batch gets its own signal in order | `raft/coalescer.rs` unit tests |
| T5 | **Crash test of (a): no acknowledged lease is lost.** The child prints an ACK when its ticket completes at `logged`. With the apply delay hook, at least 15 of 20 kills land between the commit and the apply. After each restart every ACK is in the rows at its revision or later, the table equals the rows, and no address went to two clients | `crates/tenko-dhcp/tests/lease_crash.rs` (extended), `bench/phase3-dhcp/scripts/crash-test.sh` |
| T6 | The first ACK leaves while the apply hook holds; a second change of the address lands after it in order; a second client's REQUEST for that address is refused; the client's RELEASE in the gap is taken | `tests/lease_store.rs` (extended, with the apply delay) |
| T7 | Regression guard: `derived().flush()` after a completion covers that change's history row, and returns when an answered change was counted lost | `tests/lease_store.rs` |
| T8 | An error after `logged`: one completion only, the gate stays open, the keys and the hold stay until the feed shows the row, and at the stop token the wait ends with the change counted unknown and the marker kept. A wrapper that drops `logged` unfired and then fails gives no ACK | `tests/lease_store.rs` (store wrappers that fail after `logged` and that drop it) |
| T9 | A store slower than `ack_wait` with 512 in flight: every change still in the queue and in the deferred list is answered at the bound (not only the first), counted, the finding raised and cleared, and the rows land | `tests/lease_write_behind.rs` (a delaying store wrapper) |
| T10 | Two REQUESTs for one free address without an offer, the store stalled for 15 s (longer than today's 10 s hold, which passes a shorter stall today): one ACK, the other dropped or answered NAK | same file |
| T10b | One ACK for A in each of these cases, the store stalled: (a) X binds A, releases it and binds it again while Y asks for A, with the first change applying before the third; (b) X's first change pending while its next change for A fails unanswered (past twice the queue, a build error), then Y asks; (c) X's first change pending while X sends a DISCOVER, the stall outlasting `offer_secs`, then Y asks. Also X's row expiring while its renewal waits, and a stall longer than a short lease: X's first change pending past its lease's end while X asks for A again | same file; `v4/engine/offers.rs` unit tests for the count, the three answers and the same-client and other-client rules |
| T11 | Slots or the queue full: answered at the hand-off up to twice the capacity, dropped as `queue` beyond; no allocation on that path. (d) Near full use, with every address of a probe window held by a pending change, a new hold returns false and the request drops; no counted slot is evicted | same file; `tests/lease_alloc.rs` (extended) |
| T12 | A change written behind and then refused: counted as lost, its address held, the marker kept at the stop | same file |
| T12b | A hold is released at every completion that did not answer: a refusal before the answer, a build error, a failed `submit`, a stop, the timer's failed pop on a store that is not a sole voter. Each time another client can take the address at once. After a drain, no slot is counted, and a lost change's release keeps its address held until the lost lease's end | same file |
| T13 | A stop under lag: answered changes are written until the stop deadline, the rest counted as lost, the marker kept | same file |
| T14 | The marker: a clean stop removes it, a kill leaves it, a start finds it, a clean stop inside an open window keeps it, a restore writes it, its content is never read | `lease/recovery.rs` unit tests; the restore test in `crates/tenko/tests/` |
| T15 | **Crash test of (b): the probe is on after an unclean restart.** The log writer is stalled by a `test-hooks` file, the load writes behind, and the child is killed and restarted. After the restart: the finding and the audit record are present; `Conflicts::effective()` is true under the Lab profile with the setting off; the lost ACKs are at most the counted ones written behind, and every other ACK is present; a free address's OFFER is probed; a fake probe that answers for a lost lease's address makes the allocator move on, so no address goes to two clients | `tests/lease_crash.rs` (a second mode) |
| T16 | Inside the window: a returning client with an expired row on the address is probed; an OFFER that cannot be parked is dropped; the window lasts to the later of the longest grant and the table's latest end; DECLINE is honored | `tests/conflict.rs` (extended, with the test clock) |
| T17 | Regression guard: DHCPv6 is never written behind; a stalled store drops at 2 s as today, after (a) | `tests/lease_write_behind.rs` |
| T19 | A store that is not a sole voter (a wrapper answering `sole_voter` false) never writes behind: a stalled commit drops at the bound, and with the slots full the request drops as `queue` without a reply | `tests/lease_write_behind.rs` |
| T20 | **The gate of LF4: a property test of the engine's offer table and the change lifecycle.** It runs random sequences over a few addresses and clients: DISCOVER, REQUEST, RELEASE, DECLINE, expiry, renewal, the operator's release, a refused or failed change, a lost change, a stop, and a store stall longer than the offer hold. Two invariants are checked. First, no address is answered to two clients while both bindings are live. Second, every counted slot frees once its changes have completed. It also asserts the slot rules of section 2.3: the count never wraps, and a counted slot is never evicted or overwritten by `grow`. Written before the code, it runs in `cargo nextest` with a fixed seed set; a seed that once failed joins the set | `crates/tenko-dhcp/tests/hold_lifecycle.rs` (the engine, the offer table and `StoreLeases` over a scripted store with a stall switch) |
| T18 | Through the binary: a killed `tenko serve` comes back with `dhcp.lease.unclean_restart` and the probe line in the log | `crates/tenko/tests/acceptance_dhcp.rs` |

The existing `lease_refusal.rs`, `lease_write_cost.rs` and `acceptance_dhcp_exit.rs` must stay green. The texts "did not commit within" and `commit_wait` are swept (CONTRIBUTING's sweep rule).

## 7. Measurements: before and after, on the shipped binary

Each run is on the musl release build of `deploy/Dockerfile`, on the two lab VMs (`bench/phase3-dhcp/scripts/run-perfdhcp.sh`, phase-3-exit section 6.1). Before and after are two builds of adjacent commits, and each run names its binary. The workstation guard (`guard.sh`) is a regression check only.

| # | What | Before (LF0) | After | Expected |
|---|---|---|---|---|
| L1 | M31 again: perfdhcp with option 81 on the VMs, and the Windows stand-in on a quiet machine | today's `main` | (not changed by this plan) | A new baseline for the DDNS work; the 2026-10-22 figures are superseded |
| L2 | M26 ceiling and M28 p50 and p99 from REQUEST to ACK at 1,000, 5,000 and 10,000/s. Before: the commit histogram, which is the answer today. After: the answer histogram beside the commit histogram | the base build with LF1's spans | after LF2 (LF3) | At 1,000/s the answer falls from 3.27 ms towards the fsync plus one hand-off (about 1 ms) and the p99 from 23.0 ms to single digits; at 5,000/s the p99 falls below 100 ms; the ceiling and the commit histogram are unchanged (apply-bound) |
| L3 | Where a commit's time goes: spans from the enqueue to `client_write_ff`, from the append to the flush, from the flush to `save_committed`, from there to the apply's end and to the wake | base | LF3 | The commit-to-apply and checkpoint shares leave the ACK path |
| L4 | `strace -f -e fsync,fdatasync` of one run: fsyncs per redb durable commit | base | LF3 | Unchanged: (a) adds no write |
| L5 | M32: 20 kills on the workstation (T5) and the owner's five power-offs | (2026-10-22) | LF3 | 0 acknowledged leases lost |
| L6 | Write-behind under a slow disk: the node VM's disk throttled in Proxmox to a low write rate, perfdhcp at 1,000/s, then a kill | after LF2 | after LF4 (LF5) | Before: drops at the 2 s wait. After: the DHCPv4 answer p99 at or below `ack_wait`, no drops up to twice the queue, the finding and the audit records, and after the kill the probe window |

The lab node VM is the lead's to set up under the lab mandate. The throttle is set on that VM only and removed after the run.

## 8. Work packages

| Package | Owner | Files | Depends on |
|---|---|---|---|
| LF0 Measure first | lab measurement | `bench/phase3-dhcp/results/<date>-m31-ddns.md` (supersedes 2026-10-22), `<date>-lease-flush-before.md`; also counted per minute during M31: the job rows (`tenko-jobs` table) the DDNS worker leaves, and the CPU of the IPAM findings refresh after a burst of new leases, so that both are on record beside the commit latency | none (L2 to L4 after LF1's spans commit) |
| LF1 Answer at the commit (store) | store builder | `crates/tenko-store/src/api.rs` (trait method with default), `raft/coalescer.rs`, `raft/log.rs` (the `index -> seq` map and its senders, `save_committed`, `truncate`, `purge`, the `test-hooks` stall for LF4), `raft/types.rs` (`seq`, `PartialEq`), `raft/mod.rs` (spans, `Store::sole_voter`), `raft/sm.rs` (the `test-hooks` apply delay), `tests/logged_answer.rs`, `CHANGELOG.md` | none |
| LF2 The DHCP answer at the commit, and the hold | DHCP builder | `crates/tenko-dhcp/src/lease/commit.rs` (the hold's release on every unanswered completion, the unknown wait), `v6/lease/commit.rs`, `store.rs` (`Answered`), `lease/derived.rs` (`flush`), `v4/engine/offers.rs` (the count per slot with `checked_add`, `Held | Other | Full`, no eviction of a counted slot and the eviction candidate over zero-count slots, `release` checking the client and leaving the slot `used`, `grow` never overwriting a counted slot, sizing), `v4/engine/mod.rs` (the counted hold at `:990` at `offer_secs`, `Full` dropping as `Queue` at `:990` and `:778`, the RELEASE and the DECLINE from the counted holder), `server/mod.rs` (the release on a failed hand-off and on the path after `:990` without a hand-off, `reply` returning `Drop(Malformed)` at `v4/engine/mod.rs:1018-1029`), `lease/metrics.rs` (answer histogram, unknown counter), `tests/lease_crash.rs`, `tests/lease_store.rs`, `bench/phase3-dhcp/scripts/crash-test.sh`, `docs/dhcp.md` sections 8.1, 8.2 and 8.7, `CHANGELOG.md` | LF1 |
| LF3 Measure (a) | lab measurement | `bench/phase3-dhcp/results/<date>-lease-flush-after.md`, the M32 file for the kills | LF2 |
| LF4 Write-behind and the unclean restart | DHCP builder | `tests/hold_lifecycle.rs` (T20, written first: the package's gate), `lease/commit.rs` (the release of a lost change and of the timer's failed pop, once per change; `ack_wait`, the deadline FIFO and the answered set at full size, their timer arm, the cached sole-voter flag, the queue at twice its size, the stop), `server/mod.rs` (`hand_off`'s no-slot path reading the flag and replying after an `Ok` submit, `commit_loop`), `lease/metrics.rs`, `role.rs` (findings, audit), new `lease/recovery.rs`, `conflict/mod.rs` (the window, `park` inside it), `conflict/rules.rs` (the bound-row rule), `conflict/scan.rs` (`choose`), `crates/tenko/src/serve/dhcp.rs` (marker, `choose`), the restore step in `crates/tenko/src/backup/` (the marker), `ui/i18n/en.d/labels.xlf` and `sv.d/labels.xlf`, `tests/lease_write_behind.rs`, `tests/lease_alloc.rs`, `tests/lease_crash.rs`, `tests/conflict.rs`, `crates/tenko/tests/acceptance_dhcp.rs`, `docs/dhcp.md` sections 8.6, 10.6 and 14.5 (with a part for the operator on the worst case: at most 8,704 leases lost at the cap, about 0.9 s of load at 10,000 per second, why that is the bound, why a client's lease is put before the disk, and what protects the addresses afterward: the hold, the probe window and DHCPDECLINE), `docs/dhcp-contracts.md` section 8, `CHANGELOG.md` | LF2, LF3 (the bound), LF-Q1 to LF-Q7 |
| LF5 Measure (b), then the documents | lab measurement, then the lead | `bench/phase3-dhcp/results/<date>-write-behind.md`; after the owner's word on section 9: a new ADR 0039 (proposed 0039; 0036 and 0037 are claimed by the notifications and discovery plans, 0038 by the takeover script), `docs/REQUIREMENTS.md` (DHCP-07), `docs/plans/phase-3-exit.md` (E24, M32 note), ADR 0019 and ADR 0030 status lines, `docs/plans/ha-plan.md` section 3.1 (one sentence), the requirement trace | LF4 |

LF0 to LF3, design (a), are ready to build as they stand. LF4 starts with T20: the property test is written and reviewed before the code, and LF4 merges only with T20 green on its seed set. LF1 and LF2 can merge as one gate run. LF4 waits for LF3, because the bound is set from L2. None of the packages changes a stored format: `seq` is skipped by serde, and the marker is a file without content. The backup and the upgrade copies name their files and do not copy the marker. `deploy/`, the installer and the API need no change. The new findings and metrics reach `ui/` only through the existing generic health view and the label catalog.

## 9. The documents: proposed text for the owner

These are proposals, marked so in the files until the owner accepts them. They land in LF5, after the measurement.

**DHCP-07, proposed:** "Durable lease store on each node that serves a scope, with lease history. A lease is answered once its record is committed in the serving node's log, which is group-committed (one flush per group), not after the store has applied it. For DHCPv4 on a node whose store is a sole voter (a single controller, or the node store), while that log lags past a bound, the answer may precede the write, by at most that bound in time and a bounded number of changes. The node counts and shows this, and after an unclean restart it probes every new DHCPv4 address and honors DHCPDECLINE until every lease that could have been lost has ended. DHCPv6 leases and delegated prefixes, and every lease on a controllers' group of several voters, are always answered after their commit. Leases are published to the controllers' store after the answer and never pass through the global Raft group on the DORA path."

**E24, proposed:** "Leases survive the node: the node is killed (SIGKILL, and a power-off of the lab VM) under perfdhcp load and restarted. No lease answered at its commit is lost. DHCPv4 leases answered ahead of their write while the log lagged are counted, a kill loses at most those, and the restart turns the conflict probe on for new addresses. No address is leased to two clients while the probe answers, and the role's lease table equals the store's rows. While the store refuses writes (the test hook of WP6.2) the role behaves as P3-Q14 decides." The kills of 2026-10-22 remain evidence for the first sentence; T5, T15 and L5 add the rest.

**ADR 0019 point 3, proposed amendment**, through the new ADR 0039, "When the lease answer leaves", which also amends ADR 0030 points 1 and 9:
- "The ACK or REPLY leaves when the batch's log entry is committed (on a single voter, durable on the serving node), not when it is applied; a lease batch's apply cannot refuse it."
- "For DHCPv4 on a store that is a sole voter, while the commit path lags past the answer bound (500 ms), the answer leaves at the bound and the change is written behind it. The address is held for the client by a counted hold from the engine's decision until the row lands, for every binding change, and the count is bounded and shown."
- "An unclean restart turns conflict probing on for new addresses until every lease that could have been lost has ended."
- "Renewals are written like new leases. A DHCPv4 renewal written behind can be lost by a crash, and the probe and DHCPDECLINE recover from that. DHCPv6 is not written behind."
- ADR 0019's sentence "a renewal that is not durable can let the address be given to another client after a crash" is kept as the reason for the probe.

## 10. Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| LF-Q1 | Write-behind for DHCPv4 in every profile with no setting, or off under Hardened? | **On everywhere, no setting.** Your rule is "never", (a) makes it rare, and it is always shown and audited. The alternative is a Hardened site that prefers a dropped request to a counted risk, as a profile column |
| LF-Q2 | The answer bound: a constant of 500 ms, below RFC 8415's 0.9 s and confirmed or replaced by LF3's measurement at 5,000/s? | **Yes, a constant.** It is not an operator's choice: it follows from the clients' retransmission and the measured tail |
| LF-Q3 | How much may be answered ahead of its write: the in-flight changes and twice the queue (up to 8,704 changes at the largest queue, about 0.9 s at 10,000/s and 8.7 s at 1,000/s)? | **Yes.** It is the loss window. A disk stalled for longer is a failure to show (`dhcp.lease.write_behind` says so), not to hide behind more memory |
| LF-Q4 | Probe after every start that finds the marker, or only after one during write-behind? | **Every one.** It also covers a disk or hypervisor that lied about a flush, when the marker survived. Knowing that write-behind ran would need a durable write at the very moment the disk is slow. The cost is the probe's wait (at most 300 ms) on the first offer of each new address during the window |
| LF-Q5 | The window: until the later of the longest grant the image allows and the latest end in the rebuilt table (8 days for an imported Windows default), or shorter (T1, one hour)? | **The longest grant and the table's latest end.** A client whose lease was lost and that cannot renew keeps using the address until its end. The probe costs little per new address |
| LF-Q6 | During the window, the probe overrides `conflict_detection = off` and the Lab profile, and runs without the `probe` role (the `dhcp` role builds the same `ScanProbe`)? | **Yes to all three.** It uses only what the service holds; no privilege changes (ADR 0023) |
| LF-Q7 | A store that refuses writes (a disk error, a quorum loss): keep P3-Q14 (renewals answered for their remaining time, new clients dropped), or write behind into it too? | **Keep P3-Q14.** Write-behind into a store that refuses grows without end and promises leases that never land. Slice 12's node store removes the quorum case |
| LF-Q8 | The document changes of section 9 as ADR 0039 plus the DHCP-07 and E24 texts, written after LF3 and LF5? | **Yes.** The texts follow what was measured, not what was expected |
| LF-Q9 | DHCPv6 write-behind later? It would need, for IA_PD, a duplicate check for delegated prefixes after an unclean restart (none exists: no DAD and no DECLINE for prefixes), for example holding new delegations from prefixes delegated within the window. For IA_NA it would rely on the clients' DAD (the IPv6 duplicate address check) and DECLINE alone, because the probe is IPv4 only | **Not now.** (a) already removes most of the v6 latency; revisit only if L6 shows v6 drops under load the owner cares about |
