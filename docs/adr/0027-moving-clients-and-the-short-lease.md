# ADR 0027: Moving clients and the short lease before a move

- Status: Accepted (the owner decided the design on 2026-10-26)
- Date: 2026-10-26

## Context

A move job (IPAM-19, [moves.md](../moves.md)) changes a device's network and then waits until the device is seen at its new address; past its deadline it rolls back. Until now the deadline was half the target pools' lease time, the point at which a client renews.

Reasoning through RFC 2131 shows that this point is not what a moved client does. At T1 (half the lease) a bound client unicasts a REQUEST to its server. A client whose network changed under it keeps its old address and cannot reach its old gateway, so that REQUEST never leaves it; a NAK the server could send would go out as a broadcast on the server's own link or be routed to the old network (RFC 2131 section 4.3.2), and neither reaches the client. At T2 (seven eighths) the client broadcasts its REQUEST, the relay of the new network adds its `giaddr`, which selects the target scope, the engine NAKs the address of another network (the scope is authoritative), and the client DISCOVERs and gets its new address. A client that does not react to the link change therefore comes back at T2 or at the end of its lease, never at T1: with the default lease of a day that is about 21 hours, not 12.

The one thing within the RFCs that shortens the wait is a short lease handed out before the network changes, per client, at the client's next normal renewal, which still reaches the server because the client is still on its old network. The owner decided on 2026-10-26 that the job does exactly that, waits for that renewal (bounded), and computes two times from the client's real lease: when its next DHCP message is expected, and the migration deadline.

The engine must therefore know, on the DORA path, which client a move job moves and for which address, without allocating (the rule of `tests/alloc.rs`) and without a controller round trip (CONTRIBUTING rule 5). The job must also see what the client does near its deadline and when it reconnects on the target network, which the lease table does not show: a NAK and a DISCOVER commit nothing.

## Decision

1. **A moving client is a row of its own, `dhcp.moving`, keyed by the job.** `MovingClient` names the job, the client's MAC address, the old lease (VRF and address) whose renewal gets the short lease (absent for "move now"), the short lease's time, the target scope, an `until` (the job's own deadline) and whether the job extended its deadline. The move job writes it in its first step, `ipam.move.prepare`, staged with the step's state; the cleanup removes it with the confirmed move; every compensation of a move step removes it first, so the rollback drops it before anything is undone.
2. **The stored lease row does not change.** A marker on `dhcp.leases` would change its data format (the compact row of `lease::row` and the CBOR row) and would be written by two writers, the committer and the job, with the committer's version precondition between them. The new table is an addition: no existing row, key or format changes.
3. **The role serves the rows in its configuration image.** `dhcp.moving` is a table of the `dhcp` node role (`NODE_TABLES`); the feed carries it and the image holds it as `tenko_dhcp::moving::Moving`, sorted by MAC address with an index by old lease. The engine reads it without allocating: a REQUEST (and its OFFER) for the old address of an active row's client is granted at most the short lease, with T1 and T2 derived from it as for any grant; every message of a moving client's MAC address is noted with two relaxed atomic stores (its last message, and its last message on the target scope). A new image takes the activity of the rows it keeps from the image it replaces.
4. **A row counts only while its job is active.** The engine ignores a row past its `until`. The leader's lease expiry (`dhcp.expiry`), which follows `dhcp.leases`, removes rows whose job is gone or ended and rows past their `until`, so a job that failed without removing its row leaves nothing behind.
5. **The job's clock moves its waiting steps.** A leader service, `ipam.moves`, completes the wait for the short lease (`ipam.move.lease`) when the lease table shows it or the expected renewal did not come, sets the observation's migration deadline when the step starts, shortens it to a verification window once the client's exchange on the target scope is seen, extends it once when the client is in the middle of an exchange at the deadline, and completes the observation when the client holds its new lease on the target scope. The job engine gains one operation for it, `JobEngine::set_manual_deadline`, which sets the deadline of a step waiting for a person (the existing `deadline` of `StepState::WaitingForManual`, which the machine now honours) and records it in the transition log.
6. **Every value is a setting.** `[dhcp.moves]`: `short_lease_secs` (120), `prepare_limit_secs` (3,600), `verify_secs` (90), `margin_secs` (60), `deadline_limit_secs` (172,800), `extend_window_secs` (15), `extend_secs` (60). The submit copies them into the job, so a running job keeps the values it was previewed with.

## Consequences

- A client the job moves renews about every minute while it is still on its old network, then rebinds on the new one within the short lease; the move confirms in minutes instead of hours, whatever the pool's lease time.
- One more table on the node role and in the image; an image rebuild per marker written, removed or extended (a few per job, never per DHCP message). The DORA path pays an empty-check per message without moves, and a binary search over the active moves of the moment with them; M26 is unchanged within its noise.
- The client's activity lives in the memory of the role that served it. In Phase 3 the role and the job run in one process; a fed `dhcp` node of ADR 0025 decision 11 will need the activity reported to the controllers (a node report, or a column of the published copy) before the clock sees it there. Without it the clock still sets the deadline from the lease table and verifies by the new lease; only the extension and the early verification window are lost.
- The job engine's contract gains `set_manual_deadline`; `StepOutcome` and the step handler trait are unchanged.
- The deadline of a move can be longer than before (the end of the client's lease instead of half the pool's lease) when Tenko does not serve the old network or the job could not prepare; the limit bounds it, and a request's own timeout still replaces it.

## Alternatives considered

- **A NAK at T1.** It cannot reach a moved client (see Context); `tests/engine_moves.rs` documents why so no one builds on it again.
- **The marker in the stored lease row.** Changes the data format and puts two writers on one row (decision point 2).
- **The marker in memory only, set through the role port.** Works in one process and is rebuilt by the job at restart, but needs its own rebuild logic, does not reach a fed `dhcp` node and cannot be seen by the leader's cleanup; the row in the image does all three with the existing feed.
- **A polling observation step.** A step that waits in `execute` holds a runner worker for the whole observation (up to the limit, two days) and leaves a person no task to confirm; a waiting manual step with a deadline the clock moves holds nothing.
- **Forcing the client off its port (a port bounce, a client kick).** Faster still, but a change on the switch or the access point with side effects; it is the second part of the moves work and stays out of this decision.
