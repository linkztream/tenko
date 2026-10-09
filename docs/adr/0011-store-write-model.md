# ADR 0011: Store write model

- Status: Accepted
- Date: 2026-10-09

## Context

ADR 0002 chose an embedded Raft store (`openraft` over `redb`) with writes coalesced into Raft entries, and left open how application writes are expressed, how audit records relate to the changes they describe, how live updates are replayed after a reconnect, and how replicas of different versions apply the same log identically during a rolling upgrade (OPS-08). The Phase 1 execution plan (`docs/plans/phase-1-execution.md`, section 2.4 and 2.5) proposed one model for all of these, and the owner accepted it on 2026-10-09.

## Decision

1. **A write is a `WriteBatch`**: the principal (mandatory, NEVER-03), the proposer's timestamp, an optional request id and idempotency key, a list of **preconditions**, a list of **physical mutations** (`Put`, `Delete`, `Bump` on a counter) and a list of **audit drafts**. The proposer computes the mutations from a read view; domain logic never runs in the state machine, so every replica applies a batch identically regardless of its software version.
2. **Preconditions are checked deterministically at apply**: a version precondition (`expect: Option<Revision>` per key, `None` meaning "must be absent") and a counter precondition (for example the per-VRF prefix-tree version). A failed precondition fails the whole batch with the list of failures, and the caller re-reads and retries.
3. **One store-wide `Revision` per applied batch**, incremented by exactly one. A batch is atomic. Batches that share a Raft entry (ADR 0002 decision 4) apply in order, each against its own preconditions.
4. **Audit is part of the batch.** The state machine turns the drafts into `AuditRecord`s at apply, assigning a gap-free `AuditSeq` and the hash chain (`prev`, `hash` as SHA-256 over the canonical CBOR of the record), so a change and its audit record always commit together and the chain is identical on every replica (IAM-18, NEVER-02). Denied or failed actions are batches with audit drafts and no mutations.
5. **Idempotency keys** (API-04): a replay of the same key returns the first `Committed` with `replayed: true`; a different batch under the same key is rejected.
6. **A journal of `ChangeSet`s** (`sys.journal`: revision, principal, time, changed keys with a deleted flag) feeds `watch(from, filter)` and the SSE stream. SSE event ids are revisions (ADR 0008); a client that asks for a revision older than the retained journal receives `reset` and reloads.
7. **Reads are MVCC views** at a revision (`Local`, `AtLeast(revision)` for read-your-writes, `Linearizable`), never through Raft.
8. **Derived indexes** (the in-memory serving structures of ADR 0002) are built aside from a read view and installed atomically; a snapshot install never clears a live index. Incremental updates apply in revision order.
9. **Encoding**: keys are order-preserving binary (big-endian integers, UUID bytes, IP family byte plus octets); values are CBOR with defaults on new fields so mixed versions coexist. One canonical CBOR encoding is used wherever bytes are hashed.
10. **Plaintext secrets never enter a batch** (NEVER-01). Tables that may hold secrets accept only vault envelopes.
11. **`MemStore` implements the same trait** with the same semantics, and one conformance suite tests both stores. Every Phase 1 package builds against `MemStore` until the Raft store merges.

## Consequences

- Application crates become pure functions from a read view to a `WriteBatch`, which makes dry runs, import previews and job previews the same code path (`plan` then `apply`).
- Rolling upgrades are safe by construction: an old replica can apply a batch produced by a new one, because the batch carries no domain logic.
- The audit chain costs one SHA-256 per record on the apply path of the controller, not on the data plane; the chain is verifiable offline with `tenko audit verify`.
- Live update replay across controllers needs the journal to be replicated state, which it is, because it is written by the state machine.
- Preconditions make optimistic concurrency the default; hot counters (the per-VRF tree version) are the retry points and are measured in Phase 1.
- The model adds a layer over openraft's own log; the coalescer, the precondition checker and the journal are Tenko code with their own tests and the conformance suite.

## Alternatives considered

- **Domain commands in the Raft log** (the state machine runs the IPAM logic). Simpler proposers, but every replica must run identical domain code, which breaks rolling upgrades and makes the state machine the place where bugs become permanent divergences.
- **Audit written separately after the change.** A crash between the two leaves changes without records or records without changes; the chain would have holes.
- **Per-table revisions.** Finer-grained SSE, but no single ordering for replay and audit; one store-wide revision is simpler and the journal filter gives the same selectivity.
- **Last-writer-wins without preconditions.** Lower retry rates but silent lost updates in a multi-user IPAM, which is exactly the spreadsheet problem being replaced.
