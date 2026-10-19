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
| [0002](0002-storage-and-replication.md) | Storage and replication | Accepted with conditions (Spike A passed 2026-10-09) | 2026-10-09 |
| [0003](0003-embedded-spa-ui.md) | Embedded single-page UI | Accepted (mechanism refined by ADR 0008) | 2026-10-09 |
| [0004](0004-single-binary-roles.md) | Single binary with roles | Accepted | 2026-10-09 |
| [0005](0005-ipam-intent-hub.md) | IPAM as the intent hub | Accepted | 2026-10-09 |
| [0006](0006-connector-architecture.md) | Connector architecture | Accepted (boundary refined by ADR 0012) | 2026-10-09 |
| [0007](0007-delivery-order.md) | Delivery order | Accepted | 2026-10-09 |
| [0008](0008-ui-embedding-and-sse.md) | UI embedding, static serving and SSE | Accepted | 2026-10-09 |
| [0009](0009-dns-wire-format-and-udp-io.md) | DNS wire-format crate and UDP I/O design | Accepted | 2026-10-09 |
| [0010](0010-webauthn-relying-party.md) | WebAuthn relying-party implementation without OpenSSL | Accepted | 2026-10-09 |
| [0011](0011-store-write-model.md) | Store write model | Accepted | 2026-10-09 |
| [0012](0012-connector-plugins.md) | Connectors as plugins over a published protocol | Accepted | 2026-10-09 |
| [0013](0013-partitions.md) | Partitions and multi-site ownership | Accepted | 2026-10-11 |
| [0014](0014-controller-cluster.md) | The controller cluster | Accepted | 2026-10-10 |
| [0015](0015-scoped-authorization.md) | Scoped authorization, service accounts and scoped tokens | Accepted | 2026-10-11 |
| [0016](0016-backup-and-restore.md) | Backup and restore | Accepted | 2026-10-11 |
| [0017](0017-dns-data-model-and-serving-path.md) | DNS data model and serving path | Proposed | 2026-10-17 |
| [0018](0018-dnssec-key-handling-and-signing.md) | DNSSEC key handling and signing | Proposed | 2026-10-18 |
