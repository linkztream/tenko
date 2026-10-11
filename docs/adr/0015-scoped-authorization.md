# ADR 0015: Scoped authorization, service accounts and scoped tokens

- Status: Accepted
- Date: 2026-10-11

## Context

Through Slice 2 a role applied to the whole installation. `ScopeFilter::Only` and the error `auth.out_of_scope` existed in `tenko-core`, but nothing produced them, personal tokens acted with the full roles of their owner, and the multi-factor requirement (TGL-02, TGL-03) was the same for every account. Slice 3 closes three requirements (plan section 2.5, WP3.2):

- **IAM-01.** Object-based RBAC scoped per prefix and site (zones and DHCP scopes follow in Phases 2 and 3), with delegation. A VRF scope is added because every prefix and address already belongs to one.
- **IAM-06.** The multi-factor requirement is configurable per role.
- **IAM-10.** Scoped API tokens with expiry, and service accounts.

Two risks shape the design. R24: a scope check is missed on some endpoint or event path (search, export, history, topology, SSE) and leaks objects, or the checks cost too much on lists and fan-out. R25: a rollback to an older build reads a restriction it does not know and widens access. Owner decision S3-Q18 (accepted) adds an `auditor` role for people who read the trail without seeing the inventory.

Authorization runs on every request and must not read the store (ADR 0011, decision 8), so whatever it needs lives in a derived index that follows the commits in revision order.

## Decision

1. **Storage.** Global roles stay in `UserRecord.roles` with their present meaning. Scoped grants live in the table `auth.grants`, scoped tokens in `auth.scoped_tokens` (with the owner index `auth.user_scoped_tokens`), and the multi-factor policy per role in `auth.role_policies`. An older build reads none of these tables, so after a rollback a scoped grant or a scoped token grants nothing: it is refused, never widened (R25). `UserRecord.kind` (`person` by default, `service`) is a new field with a serde default.
2. **What a grant is.** A grant is (subject, role, scope) with `granted_by`, `granted_at`, `delegable` and `parent`. The subject is a person or a service account. The role is `operator` or `viewer`; `admin` and `auditor` are global-only roles. The scope is a VRF, a site with or without its subtree, or a prefix with or without its subtree. Tenant and single-object rules exist in the core model but are not granted in Phase 1.
3. **Evaluation in three steps** (`tenko_auth::authz`). *Reach:* a global role that allows the action on the kind reaches everywhere; otherwise the scoped grants whose role allows it reach the objects their rules cover; otherwise the request is refused with `auth.forbidden`. *Strength:* the session must meet the strictest of the profile, the PIN coupling rule and the role policies, else `auth.step_up_required`. *Scope:* the anchors of the object must be covered, one anchor for a read, all anchors for a create, update or delete, else `auth.out_of_scope`. Tenants, VRFs, sites and custom field definitions are readable by every scoped principal as context. Imports, connectors, nodes, secrets, settings, users, sessions, tokens and the system are global-only in Phase 1. A check against `anywhere(kind)` passes when some grant reaches the kind, and the caller then filters a list or checks each planned object. A check against the nil identifier of a scoped kind is refused, so a caller that does neither leaks nothing: routes are deny by default (R24).
4. **Anchors** come from `tenko_ipam::scope::ScopeIndex`, a derived index over the `ipam.*` tables. A prefix anchors to itself, its ancestors, its VRF (and tenant) and its site; a range and an address to their most specific prefix; a host to its site and the prefixes of its addresses; an interface to its host; a VLAN to its site; observations and proposals to the prefix of their subject address; a job to its targets. The index answers from memory, so authorization opens no read transaction.
5. **Writes are planned first.** A scoped principal's change is planned, and every planned change is checked in all-anchors mode before and after it. An object cannot be moved out of a prefix the principal does not hold, nor into one it does not hold. Binding an interface or an address needs the right to change its host, before and after. Where a create or an address or network change lands is checked before planning as well, so a planning error (an overlap, a taken address) never describes an object outside the scope.
6. **Host creation.** A prefix-scoped principal creates a host only through `POST /hosts/bulk` with `create_interface`, `create_address` or `allocate_address` operations, so that the host has at least one address and every anchor of the resulting host lies inside the scope. A host without addresses has no prefix anchor and needs a global role.
7. **Delegation.** The holder of a delegable grant may grant a role no higher than its own over a scope inside its own grant, to people and service accounts. The new grant records the delegating grant as `parent`. Revoking a grant revokes every grant issued under it, at any depth, in the same batch. Tokens never create or revoke grants. Every change is audited as `auth.grant.create` and `auth.grant.revoke`.
8. **Service accounts.** A service account is a `UserRecord` with `kind = service`. It has no password, passkey or session; a sign-in with its name is refused like any unknown account, and setting a password on it is refused with `auth.service_account.no_login`. An administrator creates it and is recorded as its owner. It holds global roles or grants, and acts only through scoped tokens.
9. **Scoped tokens.** A scoped token carries grants that are a subset of its owner's (a role no higher, a scope inside one of the owner's), plus the special scopes `metrics` and `audit:read`. The effective right of a request is the intersection of the token's grants and the owner's grants at request time, so a token loses rights when its owner does. The expiry cap of TGL-05 is re-checked at every use, so a tightened cap shortens existing tokens. A person creates scoped tokens for themselves with `POST /auth/tokens` (with `grants` or `scopes`); an administrator creates them for a service account with `POST /access/service-accounts/{id}/tokens`.
10. **Multi-factor policy per role (IAM-06).** Each role has a policy `optional`, `totp_or_stronger` or `passkey` in `auth.role_policies`. The default is the profile's value (TGL-02, TGL-03). The effective requirement of a user is the strictest of the profile floor and the policies of every role the user holds at any scope, global or granted. It is enforced through the existing step-up path. A stored policy weaker than the profile has no effect beyond the profile.
11. **Auditor (S3-Q18).** A global-only role that reads the audit log, the audit export status and the system status, and nothing else.
12. **Filtering.** Every list, tree, search, history, export, observation, proposal, job, topology and audit route applies the scope. Lists filter before paging, so pages stay full. The prefix tree shows the out-of-scope ancestors of an in-scope prefix as context rows with the CIDR only (`TreeResponse.context`). A single read outside the scope answers 403 `auth.out_of_scope`. The SSE filter (`sse/filter.rs`, installed with `EventHub::set_filter`) drops references outside the scope and table-level events of topics the principal cannot read, and a frame left with no reference is not sent.
13. **Route-specific choices.**
    - An audit reader without the global audit permission but with scoped IPAM grants sees only audit records that name at least one object and whose objects are all of scoped kinds inside its scope; `GET /audit/verify` stays global.
    - An approved proposal of a scoped principal is planned and checked against its scope before it applies.
    - A move needs Update on every moved object and on the target prefix.
    - VLAN provisioning writes through a network controller, which is global-only, so it is refused for a principal whose writes are scoped.
    - CSV exports list only the objects in scope.
    - Secrets stay global-only: a scoped principal gets an empty list and a 403 on single reads.
14. **Password change requirement.** An account that must change its password gets 403 `auth.password_change_required` on every route except `POST /auth/password`, `POST /auth/password/check`, `POST /auth/logout` and `GET /auth/session`.
15. **Unlock watch.** Unlocking a user clears its login throttle on every controller: each controller follows the user records and clears its own throttle when the unlock is written.
16. **Neighbours.** WP3.5 checks `tenko_auth::authz::METRICS_OBJECT` on the metrics route, which a token with the scope `metrics` may read. The single-use challenge row in the login and enrolment batches is delivered by WP3.1b and is not part of this decision.

`docs/access.md` describes the behaviour for operators and administrators.

## Consequences

- A scoped operator sees and edits only the objects inside the granted scopes and gets 403 `auth.out_of_scope` elsewhere. A token narrower than its owner cannot exceed its grants and loses rights when its owner does. A per-role passkey policy forces step-up for the holders of that role only.
- A rollback to a build before Slice 3 does not widen anything: grants and scoped tokens sit in tables that build does not read, so they do nothing (R25). `docs/upgrades.md` section 4.1 governs the rollback itself.
- Filtering costs time on lists and fan-out. Anchors are answered from memory by a derived index and lists filter before paging; measurement M13 (`bench/phase1-rbac/`) bounds the cost: a list of 10,000 hosts for a scoped principal within 1.5 times the unscoped time, and SSE fan-out of 100 events per second to 1,000 scoped subscribers below one core.
- Deny by default: a route that makes no scope decision refuses a scoped principal instead of leaking. A new route, a new object kind or a new event topic is invisible to scoped principals until someone decides how it anchors (R24). An OpenAPI-driven test calls every route as a scoped principal and asserts that no out-of-scope object appears.
- A scoped token has one more layer than a user: the token's rules and the owner's rules must both cover an object. There is exactly one layer per token; a token cannot carry a token.
- A prefix-scoped operator cannot create a host without addresses, a VLAN provisioning job or an import. These stay with global roles in Phase 1.
- The role policy can only raise a requirement above the profile. An administrator who wants a looser rule changes the profile, not the policy.
- The authorization index holds every grant and scoped token in memory; it reloads grants and policies whole on a change, because they are few.
- Phase 2 and Phase 3 add zones and DHCP scopes as further rule kinds and anchors on the same evaluation.

## Alternatives considered

- **Scoped roles inside `UserRecord.roles`.** The smallest change to the data model, rejected: an older build deserializes the field, reads a scoped role as a global one and widens access after a rollback (R25).
- **Resolving anchors from the store for every request.** Always current without an index, rejected for cost: a list of ten thousand objects would need a read per object, against the budget of M13. The derived index follows the commits in revision order, as ADR 0011 prescribes for authorization data.
- **A separate policy engine (a rule language or an external decision service).** Flexible, rejected as heavier than needed: Phase 1 has four roles and three kinds of scope, and a general engine adds a language, a second place where decisions can differ from the code, and a way to disagree with the filtered lists.
- **Token scopes as a separate permission vocabulary.** A token would carry its own list of allowed operations. Rejected: a token carries grants of the same form as a user's and the system intersects them with the owner's, so one evaluator serves both and a token cannot gain what its owner lacks.
- **Custom roles now.** Rejected for Phase 1 (S3-Q18, option c): custom roles belong with the request and approval workflows (IAM-02, Phase 5). The fixed auditor role covers the one gap that could not wait.
