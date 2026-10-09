# Architecture Decision Records

An Architecture Decision Record (ADR) captures one significant decision: the context that forced it, what was decided, what follows from it, and which alternatives were rejected. ADRs are the project's memory of why things are the way they are.

## When to write an ADR

Write an ADR for any decision that is expensive to reverse or that other parts of the system depend on, for example:

- choice of language, storage, replication, UI technology or deployment model;
- adoption of a core library after a spike (for example the DNS wire-format crate after Spike B);
- any permission to use `unsafe` code (required by the `#![forbid(unsafe_code)]` policy, API-16);
- a change to a security property that is not a profile toggle (the never-off list, mTLS between nodes, the PIN coupling rule);
- a phase gate outcome (for example the Spike A storage gate in ADR 0002).

Requirements belong in REQUIREMENTS.md, not in ADRs; an ADR may cite requirement IDs.

## Rules

1. **One decision per file.**
2. **Numbering:** four digits, sequential, never reused. File name `NNNN-short-kebab-title.md`.
3. **Statuses:**

   | Status | Meaning |
   |---|---|
   | Proposed | Under discussion or waiting for evidence (for example a spike). May be edited freely. |
   | Accepted | In force. The text is frozen. |
   | Superseded | Replaced by a later ADR, named in the status line: `Superseded by ADR NNNN`. |

4. **Never edit an accepted ADR.** To change a decision, write a new ADR that supersedes it. The only permitted edit to an accepted ADR is changing its status line to `Superseded by ADR NNNN`. Fixing a typo or a broken link is allowed if it does not change meaning.
5. A superseding ADR states in its Context which ADR it replaces and why.
6. A Proposed ADR moves to Accepted in a change that records the evidence (for example measured results), or is superseded by an ADR that records the alternative.

## Format

```markdown
# ADR NNNN: <title>

- Status: Proposed | Accepted | Superseded by ADR NNNN
- Date: YYYY-MM-DD

## Context

## Decision

## Consequences

## Alternatives considered
```

The date is the date the ADR was written or last changed status.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-implementation-language.md) | Implementation language | Accepted | 2026-10-09 |
| [0002](0002-storage-and-replication.md) | Storage and replication | Proposed (pending Spike A) | 2026-10-09 |
| [0003](0003-embedded-spa-ui.md) | Embedded single-page UI | Accepted | 2026-10-09 |
| [0004](0004-single-binary-roles.md) | Single binary with roles | Accepted | 2026-10-09 |
| [0005](0005-ipam-intent-hub.md) | IPAM as the intent hub | Accepted | 2026-10-09 |
| [0006](0006-connector-architecture.md) | Connector architecture | Accepted | 2026-10-09 |
| [0007](0007-delivery-order.md) | Delivery order | Accepted | 2026-10-09 |
