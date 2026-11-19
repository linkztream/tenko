# Access: roles, scoped grants, service accounts and scoped tokens

This page describes who may do what in Tenko DDI: the four roles, scoped grants over VRFs, sites and prefixes, delegation, service accounts, scoped API tokens, the multi-factor policy per role, and what a scoped person sees in lists, the prefix tree, search, exports, the audit log and the event stream. It is for an administrator who gives people and automation limited access, and for a developer who adds a route and has to decide how it is scoped. It describes the behavior of `tenko-auth` (`authz`, `roles`, `grants`, `service/access`), of the anchors index in `tenko-ipam` (`scope`), and of the `/access` routes and the scoped filters in `tenko-api`; where this page and the code differ, the code is right. The requirements are IAM-01, IAM-06, IAM-10, IAM-20 and IAM-21 in [REQUIREMENTS.md](REQUIREMENTS.md); the profile values are TGL-02, TGL-03, TGL-05 and TGL-46 in [SECURITY-PROFILES.md](SECURITY-PROFILES.md). The decisions are recorded in [ADR 0015](adr/0015-scoped-authorization.md).

Terms used below: a **subject** is a person or a service account. A **global role** is a role in the roles of the user record; it applies to the whole installation. A **grant** gives a subject a role over one **scope**. An **anchor** is a place where an object sits among VRFs, sites and prefixes; scopes are matched against anchors.

Contents:

1. [Overview](#1-overview)
2. [Roles](#2-roles)
3. [Grants and scopes](#3-grants-and-scopes)
4. [Creating a host with a scoped grant](#4-creating-a-host-with-a-scoped-grant)
5. [Delegation](#5-delegation)
6. [Service accounts](#6-service-accounts)
7. [Scoped tokens](#7-scoped-tokens)
8. [Multi-factor policy per role](#8-multi-factor-policy-per-role)
9. [The auditor](#9-the-auditor)
10. [What scoped principals see](#10-what-scoped-principals-see)
11. [Password change required](#11-password-change-required)
12. [API](#12-api)
13. [Error codes](#13-error-codes)
14. [Rollback](#14-rollback)
15. [Personal preferences](#15-personal-preferences)

## 1. Overview

Every request is decided in three steps.

1. **Reach.** A global role that allows the action on the kind of object reaches every object of the kind. Otherwise the grants of the subject whose role allows it reach the objects their scopes cover. If neither applies, the request is refused with 403 `auth.forbidden`.
2. **Strength.** The session must be at least as strong as the strictest of the profile's requirement (TGL-02, TGL-03), the PIN coupling rule (IAM-07) and the multi-factor policy of every role the user holds, globally or through a grant (section 8). Otherwise the request is refused with 403 `auth.step_up_required`.
3. **Scope.** When only grants reach the kind, the anchors of the object must be covered: one anchor for a read, every anchor for a create, update or delete. Otherwise the request is refused with 403 `auth.out_of_scope`.

The three refusals are the answer of a write, of a single read and of an export. A list, the prefix tree, the search and the tag list filter instead of refusing: a principal that reaches nothing of a kind, whether no role or grant allows the read (step 1) or its session is too weak (step 2), gets `200` with no items on the lists of that kind, exactly as a principal whose scope holds no object of it (section 10). The reason is told by the single reads and the writes of the kind, which carry the refusal and its code. Nothing leaks either way; a client that wants the reason asks for one object.

Authorization reads no table while it decides. The roles, grants, tokens and policies are kept in an index that the store updates in commit order, so a revoked grant, a disabled account or a removed token takes effect with the commit that made it, on the controller that serves the request once it has applied that commit.

Global roles stay in the user record. Grants, scoped tokens and role policies are stored in their own tables (section 14).

## 2. Roles

| Role | May | Held |
|---|---|---|
| `admin` | Everything, including users, security settings, secrets and the system. | Globally only |
| `operator` | Reads the inventory (tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, custom fields, jobs, observations, proposals, imports, connectors, nodes, the system) and, in addition, users, settings and operator-secret metadata. Creates, changes and deletes tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, imports and connectors. Runs jobs, imports and actions on prefixes, hosts, addresses and connectors. Approves proposals. Reveals operator secrets under the reveal policy. Cannot administer, and cannot create custom fields. | Globally, or through a grant |
| `viewer` | Reads the inventory kinds listed for the operator, jobs and imports. Reads nothing else. | Globally, or through a grant |
| `auditor` | Reads the audit log and the system status, which carries the audit export warnings. Nothing else (section 9). | Globally only |

DNS and DHCP: the viewer reads both, the operator reads and writes both, and the administrator also manages TSIG and DNSSEC keys. The mirrors and takeovers of a migration are the administrator's; the operator reads them.

A grant carries `operator` or `viewer`. A grant reaches only the kinds that scopes apply to: tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, custom fields, jobs, observations, proposals and DHCP scopes (which follow the grants of their prefix). The other kinds are global-only: imports, connectors, nodes, secrets, settings, users, sessions, tokens, the system, the DNS kinds, the other DHCP kinds and the migration kinds. A person who holds only grants therefore cannot run an import, change a connector, read a secret or manage users, whatever the grant says.

The role order used by delegation and by token grants is: `admin` covers every role, `operator` covers `operator` and `viewer`, `viewer` covers `viewer`, `auditor` covers `auditor`.

## 3. Grants and scopes

A grant has these fields.

| Field | Meaning |
|---|---|
| `subject` | The person or service account that holds the grant |
| `role` | `operator` or `viewer` |
| `scope` | A rule, see below |
| `delegable` | Whether the holder may grant the role over a scope inside this one (section 5) |
| `granted_by` | Who created it; absent when the system did |
| `granted_at` | When |
| `parent` | The delegable grant it was issued under; absent for a grant an administrator made |

A subject cannot hold the same role over the same scope twice (409 `auth.grant.duplicate`). The break-glass account holds the admin role only and cannot receive a grant.

### 3.1 Rule kinds

A scope is an object with `kind` and `value`.

| `kind` | `value` | Covers |
|---|---|---|
| `vrf` | the VRF id | Objects in the VRF |
| `site` | `{"id": "<site id>", "subtree": false}` | Objects of the site; with `subtree: true` also those of its child sites |
| `prefix` | `{"id": "<prefix id>", "subtree": false}` | The prefix and the objects directly in it; with `subtree: true` everything inside it |

```json
{"kind": "vrf", "value": "0190d1c2-0000-7000-8000-000000000011"}
{"kind": "site", "value": {"id": "0190d1c2-0000-7000-8000-000000000021", "subtree": true}}
{"kind": "prefix", "value": {"id": "0190d1c2-0000-7000-8000-000000000031", "subtree": true}}
```

Rules for tenants and for single objects exist in the data model but cannot be granted in Phase 1 (422 `auth.grant.invalid_scope`). A DHCP scope follows the grants of its prefix; zones cannot be granted.

The rule must name an existing VRF, site or prefix (422 `auth.grant.invalid_scope` otherwise).

**Subtree.** A rule without `subtree` covers an object whose most specific prefix (or own site) is the one named; a rule with `subtree` covers an object that has the named prefix (or site) anywhere in the chain of its ancestors.

### 3.2 Anchors

Each object kind has anchors that a rule is matched against.

| Object | Anchors |
|---|---|
| Tenant | Itself |
| VRF | Itself and its tenant |
| Site | Itself and its ancestors |
| VLAN | Its site and the site's ancestors |
| Prefix | The prefix itself and every enclosing prefix, its VRF and tenant, and the site of the nearest prefix in that chain that names one |
| Range, address | The chain of the most specific prefix that holds it, then as for a prefix |
| Host | Its tenant, its site (and that site's ancestors), one chain per prefix of its addresses, and its VRF when all its addresses are in one VRF |
| Interface | The anchors of its host |
| DHCP scope | The anchors of its prefix |
| Observation, proposal | The chain of the prefix of the subject address, merged with the objects the proposal names |
| Job | The anchors of its targets, merged; a target that does not exist yet (the address a move will create) or that IPAM does not place (a connector) is left out |

### 3.3 Read any, write all

- **Read.** An object is readable when one of its anchors is covered by a rule of a grant whose role allows the read. A host with addresses in two prefixes is readable when the principal holds one of them.
- **Create, update, delete.** Every anchor of the object must be covered, and the object must lie inside the scope both where it is and where it goes. A host with addresses in two prefixes can be changed only by a principal that holds both, or holds a rule that covers the host whole (its VRF or its site). A prefix rule never admits a write to a host that has an address outside the rule. An object that has a part with no prefix chain at all carries an empty chain and so needs a rule that covers it whole.

Writes are checked before they are planned. Every object a scoped principal's change names, and every place it writes to, must lie inside the scope before the planner reads anything: the stored object of a change, the prefix a range, an address or a prefix is created in or moved to, the host an interface or an address is bound to, the parent of a site and the site of a VLAN. An object that does not exist is outside every scope, so the answer for an object outside the scope and for one that does not exist is the same, and a planning error after this check describes only objects inside the scope. Three answers that could still count or name objects elsewhere are narrowed for a scoped principal: a duplicate MAC address warning keeps the address and leaves out the other interface, `ipam.in_use` leaves out the count, and an invalid default zone of a tenant leaves out the zone's name and reason.

A write never places an object in another group's view: giving a host or a prefix a site needs a rule that covers that site (a site rule, or a site rule of an ancestor), unless the prefix takes the site its enclosing prefixes already give it, and tying a prefix to a VLAN needs read access to that VLAN. A prefix rule therefore keeps a host where it is but cannot move it into a site.

Writes are then planned as for anybody, and every planned change is checked before and after it is applied: a prefix cannot be moved out of or into a scope the principal does not hold, and an interface or an address bound to a host needs the right to change that host before and after. A prefix created, resized or restored around existing prefixes changes the chain of each of them, so each of them must lie inside the scope where it is and where it goes, and a create or resize whose new network holds a prefix outside the scope is refused before planning. A refused plan changes nothing and answers 403 `auth.out_of_scope`. Releasing a DHCP lease needs `execute` on the DHCP scope that holds the lease, and a lease in a scope the principal may not read answers 404 `dhcp.lease.not_found`, as reading it does.

### 3.4 Writes that run later

Some writes run after the request that asked for them, as job steps or by the reconciler. Each of them is checked, when it runs, with the rights its principal holds at that moment, before it is planned and on the plan:

| Write | Whose rights | Checked |
|---|---|---|
| The steps of a move that write intent (the new address, the cleanup that removes the old one) or the network (the switch port or client VLAN through the network controller, the bounce or kick after it) | The person or token that started the move | At each step |
| The steps of a VLAN provisioning that write intent (the VLAN and prefix, their activation) or the network (the network on the controller) | The person or token that asked for it | At each step |
| The chunks of an import | The person or token that applied it | At each chunk |
| An adoption by the reconciler | The person or token that set the adoption policy in force | At each adoption |
| A change queued while the controller was cut off from its cluster | Its author | When the queue drains, before planning and on the plan; a refused change keeps no plan |

The identity is kept with the job, never a copy of its grants. A grant revoked or narrowed since the start, or an account disabled since, refuses the write: a job rolls back what its earlier steps changed and ends with `auth.out_of_scope` or `auth.forbidden`, and an adoption is recorded as failed on its proposal and not tried again until the proposal changes. A rollback undoes only what the job's own steps wrote and is not checked, so a revoked operator never leaves half a move behind. The reconciler is no four-eyes boundary: an adoption policy set by an operator limited to a prefix adopts only what that operator may change, and setting or removing a policy needs the right to change every prefix below the prefix, since the policy governs them all. A server wired without this check refuses these writes (500 `ipam.scope.unwired`) instead of applying them unchecked.

A job started under an earlier version did not record its requester: its next write is refused with 409 `ipam.job.requester_unknown` and it rolls back. Start it again.

### 3.5 Context kinds

Every principal with a grant may read tenants, VRFs, sites and custom field definitions, whatever the rule covers, so that names and forms can be shown. Changing them still needs a rule that covers them.

### 3.6 Global-only kinds and the two special objects

Section 2 lists the global-only kinds. A check "somewhere" (an object of the kind anywhere in reach) passes for a principal when some grant reaches the kind; the route then filters the list or checks each planned object. A check against the nil identifier of a scoped kind is refused, so a route that does neither leaks nothing.

Two objects are of kind system but have their own scopes for tokens: the metrics endpoint (token scope `metrics`) and the audit log (token scope `audit:read`). See section 7.

## 4. Creating a host with a scoped grant

A person whose grants cover prefixes creates a host only through `POST /hosts/bulk`, with the operations that create the host together with its addresses, so that the host has at least one address and every anchor of the resulting host lies inside the scope. The bulk endpoint of hosts accepts, besides host operations, the operations `create_interface`, `create_address` and `allocate_address`. All operations apply, or none does.

A host without addresses has no prefix anchor, so a prefix rule never covers it; creating one needs a global role.

## 5. Delegation

The holder of a delegable grant may create grants for people and service accounts, with these limits.

- The role is covered by the role of the delegating grant (an operator may hand out `operator` and `viewer`; a viewer only `viewer`).
- The scope lies inside the scope of the delegating grant. A rule lies inside another when: it is the same rule, or the same VRF; it is the same site or prefix and the outer rule has `subtree` or the inner one has none; it names a site or prefix inside the subtree of an outer site or prefix rule; or it names a prefix that is in the VRF of an outer VRF rule. Where the answer depends on data that could change (a prefix and its subtree against a site), it is no.
- The new grant records the delegating grant as `parent`. Whether the new grant is itself delegable is chosen by the delegating person; the same limits then apply to it.

Revoking a grant revokes every grant issued under it, directly or through further delegation, in the same batch. The answer lists them. Disabling or deleting an account removes its grants and the grants issued under them; enabling it again does not restore them.

Only people with a session create or revoke grants. A token never does, whatever its grants. A refused delegation is audited as a failed `auth.grant.create`. Every change is audited: `auth.grant.create` names the subject, the grant, the role, the scope, `delegable` and the parent; `auth.grant.revoke` names the subjects, the grant, the scope and every revoked grant.

An administrator (a caller who may administer users) grants any scope to anybody and has no parent. A person who is neither an administrator nor the holder of a delegable grant gets 403 `auth.forbidden` or `auth.grant.exceeds_own`.

## 6. Service accounts

A service account is an account for automation (IAM-10). It differs from a person in these ways.

- It has no password, passkey, second factor or session. A sign-in with its name fails like a sign-in with an unknown account. Setting a password on it is refused with 409 `auth.service_account.no_login`.
- An administrator creates it and is recorded as its owner. Its name shares the name space of users (409 `users.name_taken`).
- It holds global roles (`roles` at creation) or grants, like a person. A service account can receive any grant a person can.
- It acts only through scoped tokens (section 7). A personal token of a service account is refused.
- Tokens never administer, so a service account with the admin role does not count as another administrator: the only person with the admin role cannot drop it, be disabled or be deleted while only service accounts would remain (409 `users.last_administrator`).

```json
POST /api/v1/access/service-accounts
{"name": "dns-sync", "display_name": "DNS sync", "roles": []}
```

An empty `roles` makes an account that acts through grants alone. The name has 1 to 64 characters without spaces or control characters.

## 7. Scoped tokens

A personal token acts with all the roles and grants of its owner. A scoped token (IAM-10) acts with less.

**Grants of a token.** Each is a role and optionally a scope, in the form of a grant:

```json
{"role": "viewer", "scope": {"kind": "prefix", "value": {"id": "0190d1c2-0000-7000-8000-000000000031", "subtree": true}}}
```

A grant without a scope applies to the whole installation, and its role must be covered by a global role of the owner. A grant with a scope needs a role that is `operator` or `viewer`, a scope that can be granted and exists, and either a global role of the owner that covers the role or one of the owner's grants that covers the role over a scope containing the token's scope. Otherwise the request is refused with 403 `auth.grant.exceeds_own`, 422 `auth.grant.invalid_role` or 422 `auth.grant.invalid_scope`.

**Special scopes.** `metrics` lets the token read the metrics endpoint; `audit:read` lets it read the audit log. Both read only (a third, `mirror:<id>`, is declared for the push of a mirrored source, whose routes are not built yet; it cannot be requested here): the token reaches nothing else through them; its lists of the other kinds are empty and their single reads are refused with 403 `auth.forbidden` (section 1). An owner may ask for a special scope if it is a service account or holds a global role that reads the system. A token needs at least one grant or one scope.

**Intersection.** The effective right of a request is the intersection of the token's grants and the owner's grants at that moment. An object must be covered by the token's rules and by the owner's rules. A token therefore loses rights when its owner loses them, is refused when the owner is disabled or deleted (the scoped tokens of a deleted account are removed), and never gains rights its owner gains later. A token also acts only while the sign-in that created it meets its owner's requirement: when a profile, a setting, a role policy or the first operator secret in the vault raises it, the token is refused with 403 `auth.step_up_required` until a stronger sign-in creates a new one. A token cannot administer: changing users, settings, the system, tokens, sessions or secrets, revealing a secret, and every administrative action need an interactive session.

**Lifetime.** `expires_in_days` defaults to the maximum of the profile (TGL-05: 365 days in Home, 90 in Standard, 30 in Hardened, no maximum in Lab) and may not exceed it (422 `auth.token.lifetime_exceeded`). The cap is checked again at every use against the creation time of the token, so tightening it shortens the tokens that exist.

**Creating.** A person creates a scoped token for themselves with `POST /auth/tokens` and `grants` or `scopes` in the body; without them the call creates a personal token. An administrator creates one for a service account with `POST /access/service-accounts/{id}/tokens`. The session that creates a token must meet the strength required of its user and have signed in within the last five minutes (403 `auth.step_up_required` with `required: fresh` otherwise); for a service account's token it must also meet the account's requirement. A password change or an administrator's reset revokes the owner's personal and scoped tokens. The secret (`tnk_...`, or `tnkc_...` for a renewable or bound token, section 7.1) is shown once; the listing shows the first characters only. An owner holds at most 500 scoped tokens, superseded ones kept for reuse detection included (409 `auth.token.limit`).

```json
POST /api/v1/access/service-accounts/0190d1c2-0000-7000-8000-000000000002/tokens
{
  "name": "ipam-readonly",
  "expires_in_days": 30,
  "grants": [
    {"role": "viewer",
     "scope": {"kind": "site", "value": {"id": "0190d1c2-0000-7000-8000-000000000021", "subtree": true}}}
  ]
}
```

```json
POST /api/v1/access/service-accounts/0190d1c2-0000-7000-8000-000000000002/tokens
{"name": "prometheus", "expires_in_days": 90, "scopes": ["metrics"]}
```

Creating a token is audited as `auth.token.create` with the grants and scopes; revoking one as `auth.token.revoke`.

### 7.1 Renewal (IAM-20)

A token of a service account may renew itself, so that an integration keeps working past the lifetime of TGL-05 without a person creating a new token by hand.

**The right.** `"renewable": true` in the creation request gives the token the right, under the creation rules above (an administrator with a fresh sign-in). The answer then carries a **renewal secret** (`tnr_...`, 256 random bits) beside the token, shown once like the token. The right needs TGL-46 ("Service-account tokens may renew themselves": on in Home, Standard and Lab, off in Hardened). With TGL-46 off, a creation request with the right is refused with 403 `auth.token.renewal_refused` (`reason: disabled`) and no token renews, whatever its flag says; turning it on under Hardened is a recorded deviation like the other toggles. A person's own tokens never renew (400 `auth.invalid_request`); a person creates a new one.

**The token form.** A token with the renewal right or with source prefixes (section 7.2) starts with `tnkc_` instead of `tnk_`, and so does every token a renewal returns; a plain scoped or personal token keeps `tnk_`. The form and the record go together: a record with a renewal right or source prefixes is accepted only when its token is presented as `tnkc_`, a record without them only as `tnk_`, and any other pairing is refused like an unknown token and audited as `auth.token.form_refused`. A build that does not know these constraints accepts `tnk_` only, so it refuses a constrained token before it reads or writes its record (section 14).

**The renewal secret** is stored only as its SHA-256 hash on the token's record, never logged and never accepted as a bearer token: it starts with `tnr_`, and every other route refuses it like an unknown token. It is sent only in the body of the renewal call.

**The call.** `POST /api/v1/access/token/renew`, authenticated by the token itself (`Authorization: Bearer tnkc_...`), with `{"renewal_secret": "tnr_..."}`. It answers 200 with a new token, a new renewal secret and the token's description (`expires_at` among it). The new token has the same owner, name, grants, scopes and source binding (section 7.2), except a grant its account no longer holds, which is dropped; a token left with no grant and no scope does not renew (403 `auth.grant.exceeds_own`). Its lifetime is the one the family's first token was created with, counted from the renewal and capped by the profile's maximum at that moment. A renewable token always expires: in Lab, which has no maximum, a creation request with the right and without `expires_in_days` is refused with 400 `auth.invalid_request`. A token and its successors form a **family**. The renewal is audited as `auth.token.renew` with the old and the new token.

**The old token** stays valid until the new one is used for the first time, or until its own expiry, whichever comes first, so an answer lost on the way does not lock the integration out: it still holds the old token and secret. Renewing again with the old token while the new one is unused replaces the unused one: it is kept as superseded, and presenting it later counts as reuse, since an integration that lost the answer never held it. The first use of the new token, or a renewal with it, supersedes the old one.

**Reuse detection.** A use of a superseded token, as a bearer token or in the renewal call, or of a superseded renewal secret, means that two parties hold the family's secrets. It revokes the whole family at once: every token of it is refused from that commit on. In the first minute after the supersede the old token is only refused, without revoking anything, since requests the integration sent before it switched may still arrive. Reuse detection applies only to presentations that pass the source check of section 7.2: a superseded token presented from outside its prefixes is refused and audited as `auth.token.source_refused`, and nothing more. A family keeps its eight most recently superseded tokens for this check; an older one, and a superseded token past its own expiry, is refused like an unknown token and revokes nothing. The newest token stays in the token list as revoked, with the reason, and the health warning `auth.token.revoked` stands until an administrator removes that entry (`DELETE` on it), which is the acknowledgment. The detection is audited as `auth.token.reuse_detected` with the token that was presented and the client address. An integration must therefore store the new token and the new secret together before it uses the new token.

**A wrong renewal secret** with a valid token is refused with 403 `auth.token.renewal_refused` (`reason: wrong_secret`) and audited as a failed `auth.token.renew`. The third wrong secret within a family revokes the family as above, with the reason `renewal_failures`: the secrets carry 256 bits, so a wrong one comes from someone who holds the token without the secret, or from an integration that lost its secret; neither may go on renewing. The count is reset by a successful renewal. The rate limits of every request apply in addition.

**Revoking.** `DELETE /access/service-accounts/{id}/tokens/{token}` on any token of a family removes the whole family, and so does a token that revokes itself with `DELETE /auth/tokens/{id}`; a renewal committed in between makes the removal fail with 409 `auth.conflict` rather than leave its new token behind. An account's tokens end as before: a deleted or disabled account, or an end of the account's access, removes every family.

### 7.2 Source binding (IAM-21)

`"source_prefixes": ["192.0.2.0/24", "2001:db8:42::/48"]` in the creation request binds a scoped token to client addresses: at most 64 IPv4 or IPv6 prefixes, a host address written without a length. A use from an address outside them is refused with 401 `auth.unauthenticated`, exactly like an unknown token, and audited as `auth.token.source_refused` with the address. The address is the client address the server already derives: the peer of the connection, or the address a trusted proxy reports (`[tls] trusted_proxies`, through `X-Forwarded-For` or the PROXY protocol). An IPv4 address reached as an IPv4-mapped IPv6 address counts as the IPv4 address. A bound token used where the server knows no client address is refused. A prefix of length zero is refused (it would bind nothing), and an IPv4-mapped IPv6 prefix is stored as the IPv4 prefix it covers. The refusals of one token are audited once a minute, the first of them with the number of those that followed the previous record, so that a token presented from many addresses cannot flood the audit log. Renewal keeps the list; it is changed only by creating a new token, which takes a session with a fresh sign-in.

### 7.3 The token's own description

`GET /api/v1/access/token` answers any scoped token with its own description: its account (`account`, `account_name`), the token's name, prefix, grants and scopes, its creation and expiry time, whether it may renew (with TGL-46 applied) and its source binding. It carries no secret and nothing about other tokens. A session is refused with 401 `auth.unauthenticated`: it has no token.

### 7.4 Expiry warning

A service-account token with fewer than 14 days left raises the health warning `auth.token.expiring` on the start page and in `GET /system/status`, with the number of such tokens and the first end. The hourly sweep of each controller computes the token warnings (this one and `auth.token.revoked`) and writes the audit record `auth.token.expiring` once per token, which reaches the `audit` event topic and the audit export; a controller that revokes a family or removes a token computes them again at once, the others at their next sweep. The warning clears when the token is replaced by its successor's first use, removed, or revoked. Neither warning names an account or a token, since whoever may read the system status sees it; the token list of each service account shows which tokens expire and which family was revoked, with the reason.

### 7.5 A worked example

An administrator creates a renewable token for the service account of a DHCP reporting script, bound to its network (the session cookie of a fresh sign-in is in `cookies.txt`):

```sh
curl -sS -b cookies.txt -H 'Origin: https://tenko.example.test' \
  -H 'Content-Type: application/json' \
  https://tenko.example.test/api/v1/access/service-accounts/0190d1c2-0000-7000-8000-000000000002/tokens \
  -d '{"name": "dhcp-report", "scopes": ["metrics"], "renewable": true,
       "source_prefixes": ["198.51.100.0/24", "2001:db8:42::/48"]}'
```

```json
{
  "token": "tnkc_3q2-7wEXAMPLEaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "renewal_secret": "tnr_Zm9vEXAMPLEbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "info": {"id": "0190d1c2-0000-7000-8000-0000000000a1", "name": "dhcp-report",
           "prefix": "tnkc_3q2-7wE", "created_at": "2026-01-05T09:00:00Z",
           "expires_at": "2026-04-05T09:00:00Z", "scoped": true, "scopes": ["metrics"],
           "renewable": true, "source_prefixes": ["198.51.100.0/24", "2001:db8:42::/48"]}
}
```

The script uses the token, and reads what it is:

```sh
curl -sS -H 'Authorization: Bearer tnkc_3q2-7wEXAMPLE...' https://tenko.example.test/api/v1/metrics
curl -sS -H 'Authorization: Bearer tnkc_3q2-7wEXAMPLE...' https://tenko.example.test/api/v1/access/token
```

Some time before `expires_at` it renews, stores both new secrets, and only then uses the new token:

```sh
curl -sS -X POST -H 'Authorization: Bearer tnkc_3q2-7wEXAMPLE...' \
  -H 'Content-Type: application/json' \
  https://tenko.example.test/api/v1/access/token/renew \
  -d '{"renewal_secret": "tnr_Zm9vEXAMPLE..."}'
```

```json
{
  "token": "tnkc_Q1w2EXAMPLEccccccccccccccccccccccccccccccc",
  "renewal_secret": "tnr_R5t6EXAMPLEdddddddddddddddddddddddddddddddd",
  "info": {"id": "0190d1c2-0000-7000-8000-0000000000a2", "name": "dhcp-report",
           "prefix": "tnkc_Q1w2EXA", "created_at": "2026-03-20T09:00:00Z",
           "expires_at": "2026-06-18T09:00:00Z", "renewed_at": "2026-03-20T09:00:00Z",
           "scoped": true, "scopes": ["metrics"], "renewable": true,
           "source_prefixes": ["198.51.100.0/24", "2001:db8:42::/48"]}
}
```

If the answer is lost, the script repeats the call with the old token and the old secret; the unused new token is replaced. Do not send an `Idempotency-Key` with this call: its answer carries secrets and is never stored, so a retry under the same key is refused with 409 `sys.idempotency_not_replayable` instead of answered again.

Once the new token has been used, the old one is superseded. If someone presents it again, here from a copy of the old configuration, the family is revoked:

```sh
curl -sS -H 'Authorization: Bearer tnkc_3q2-7wEXAMPLE...' https://tenko.example.test/api/v1/metrics
```

```json
{"type": "about:blank", "title": "Unauthorized", "status": 401, "code": "auth.unauthenticated",
 "detail": "authentication required"}
```

From then on the new token is refused the same way, the token list shows the family's newest token as revoked with the reason `reuse_detected`, the audit log holds `auth.token.reuse_detected` with the address the old token came from, and the start page shows `auth.token.revoked` until an administrator has looked into it and removed the revoked token. The integration needs a new token from an administrator.

### 7.6 In a cluster

Token records replicate through the store like every other record, and each change above is one write of the store, ordered with every other write: the renewal, the first use of a new token (which supersedes the old one in the same write), and the revocation of a family. Each write names the revisions of the records it read, so of two writes that read the same family, the second fails: a renewal with the old token and the first use of the new token on two controllers cannot both win, and two controllers that detect the same reuse revoke the family once. A detection whose write lost such a race is decided once more on the newer state; if that write fails too, its audit record is written alone. An administrator's removal of a family that a holder keeps renewing is tried up to three times before it answers 409 `auth.conflict`. A controller decides a use from its own copy, so it accepts the old token until it has applied the write that superseded it, as it does for any revoked token (section 1); the next use after that is detected as reuse. The hourly use time of a token, the expiry warning and the sweep are best effort: a write that loses to another is left for the next use or sweep.

### 7.7 Certificate binding (IAM-23)

`"lineage": "<lineage id>"` in the creation request binds a service-account token to an integration certificate of that account (ADR 0035, `docs/integrations.md`): the lineage must be current or pending, and of the same account, or the request is refused with 400 `auth.invalid_request` naming `lineage`. A bound token starts with `tnkb_`, and every token a renewal of it returns is bound to the same lineage. It is accepted only on the integration listener, over a connection whose client certificate belongs to that lineage. The binding is checked right after the token's form and before anything else of it: presented without the certificate, or with another lineage's, it is refused with 401 `auth.unauthenticated` like an unknown token and audited as `auth.token.binding_refused` (once a minute per token, as in section 7.2), and it never counts as reuse or as a wrong renewal secret, so a bound token copied from a log revokes nothing. Presented with the certificate, a superseded bound token is reuse as in section 7.1, and it revokes the lineage too.

A lineage that is revoked takes its bound tokens with it, in the same commit; a lineage whose certificates have all expired loses its tokens at the next hourly sweep (audited as `auth.client_cert.lapse`), since its recovery is a new enrollment and new tokens. Under TGL-47 with certificate-bound tokens required (Hardened), every token an administrator creates for a service account must name a lineage, and turning the requirement on removes the service accounts' unbound tokens at once; turning it off again revives none of them.

## 8. Multi-factor policy per role

The multi-factor requirement (IAM-06) is set per role. A policy has one of three values.

| Value | A session must be |
|---|---|
| `optional` | Any session that meets the other rules |
| `totp_or_stronger` | A password with TOTP or a recovery code, or a passkey |
| `passkey` | A passkey or a hardware security key |

**Defaults.** Without a stored policy a role follows the profile: `passkey` for the admin role when the profile requires a passkey for administrators (TGL-03); otherwise `totp_or_stronger` for every role when the profile requires multi-factor for everyone, and for the admin role when it requires it for administrators (TGL-02); otherwise `optional`.

**Strictest wins.** The requirement of a user is the strictest of the profile floor and the policies of every role the user holds at any scope: the global roles and the roles of grants. A policy weaker than the profile has no effect beyond the profile. The result is enforced through the existing step-up path: a session that is too weak gets 403 `auth.step_up_required` with the required strength on a write and on a single read, and empty lists (section 1).

| Profile (TGL-02, TGL-03) | Stored policy of `viewer` | Viewer must have |
|---|---|---|
| Standard (administrators only) | none | `optional` |
| Standard | `totp_or_stronger` | `totp_or_stronger` |
| Standard | `passkey` | `passkey` |
| Hardened (everyone, passkey for admins) | `optional` | `totp_or_stronger` (the profile wins) |
| Hardened | `passkey` | `passkey` |

A person who holds `viewer` over one prefix and `operator` over another needs the stricter of the two policies. A person with a global `viewer` role and a policy `passkey` on `operator` is not affected until a grant of `operator` is made.

The policies are read with `GET /access/role-policies`, which lists the four roles with the requirement in force (`mfa`), the profile's (`profile_default`) and the stored policy (`stored`, absent when the role follows the profile). `PUT /access/role-policies/{role}` stores a value and `DELETE` makes the role follow the profile again. Both need the right to change settings and a session that signed in within the last five minutes (403 `auth.step_up_required` with `required: fresh` otherwise), as `PATCH /settings/security` does, and are audited as `auth.role_policy.update` with the old and new value.

## 9. The auditor

The `auditor` role is global-only and cannot be granted. It reads the audit log and the system status, which carries the audit export warnings. It does not read the audit export settings (`GET /settings/audit-export` needs the administer permission on the system). It cannot read the inventory, users, settings, secrets, nodes or imports, and it cannot change anything. A viewer, by contrast, also reads the audit log through the system kind, so an installation that wants the trail read by somebody who does not see the inventory gives them the auditor role and no other.

The auditor reads `GET /audit`, `GET /audit/{seq}` and `GET /audit/verify`. A token with the scope `audit:read` reads the same audit routes.

## 10. What scoped principals see

A principal whose reach is scoped receives only what its rules cover. Lists filter before paging, so a page is full whenever more matching objects exist, and the cursor and the revision behave as for anybody.

| Route | Behavior |
|---|---|
| Lists (tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, custom fields, observations, proposals, jobs, topology) | Only objects in scope; tenants, VRFs, sites and custom fields as context |
| Lists of a kind the principal reaches nothing of | `200` with no items, never 403 (section 1) |
| Single reads and history | 403 `auth.out_of_scope` outside the scope |
| Prefix tree | The prefixes in scope as nodes; see below |
| Addresses of a prefix (`/prefixes/{id}/addresses`) | Only the addresses in scope; an address outside the scope counts as free, so the free gaps tell nothing of where it sits |
| Search | Only hits in scope |
| Exports (`/exports/*.csv`) | Only objects in scope |
| Audit log | See below |
| Proposals | Listed by the prefix of the subject address; an approval is checked before it is planned and on every plan it applies, the retries after a stale plan included |
| Running the reconciler (`POST /proposals/reconcile`) | 403 `auth.out_of_scope`: a run spans the whole installation; the reconciler runs on its own schedule |
| Observations of a subject | 403 `auth.out_of_scope` for a subject seen outside the scope and for one never seen |
| Jobs | Listed and read when every target that exists is in scope; canceled or completed when all targets are |
| Moves | Update on every moved object, on the target prefix and on the host of every moved address; a preview needs the same, since it shows what the move would write |
| VLAN provisioning | Refused, because it writes through a network controller, which is global-only in Phase 1 |
| Secrets | An empty list and 403 on single reads |
| Events | See below |

**Prefix tree.** `GET /prefixes/tree` shows the prefixes the principal may read as nodes. The prefixes it may not read that hold one it may read appear in `context`, in pre-order, so the tree keeps its shape. A context row carries only `id`, `parent`, `depth`, `cidr` and `children`; it has no name, status, utilization or other detail.

```json
{
  "nodes": [{"id": "0190d1c2-0000-7000-8000-000000000032", "cidr": "192.0.2.0/25", "depth": 1}],
  "context": [{"id": "0190d1c2-0000-7000-8000-000000000031", "cidr": "192.0.2.0/24", "depth": 0, "children": 1}]
}
```

(Fields of a node beyond those shown are omitted.)

The utilization of a node leaves out the prefixes below it that the principal may not read: their space counts as space of the node without addresses, ranges or child prefixes, so a supernet read with a rule that does not cover its children shows nothing of what they hold.

**Audit log.** A principal that may read the audit log (a global role that reads the system, the auditor, a token with `audit:read`) sees every record. A principal that does not, but whose grants reach IPAM objects, sees only the records that name at least one object and all of whose objects are of a scoped kind inside its scope. `GET /audit/verify` needs the global permission.

**Events.** The event stream carries references, never bodies. For a scoped principal the server drops the references to objects outside the scope, keeps tenants, VRFs, sites and custom field definitions, and drops table-level events (an event with no reference) of topics the principal cannot read: IPAM, jobs and discovery pass for any grant that reaches them; findings pass for any principal that reads some finding; audit, import, system, admin, connectors, secrets, cluster, metrics, `dns` and `dhcp` need a global read, or the token scope of the metrics and audit objects. A frame left with no reference is not sent. One user holds at most 16 open streams, sessions and tokens together (a browser tab opens at most two: the shell's and the start page's for `metrics`, so eight tabs fit with room for streams the server has not yet seen close), and a controller at most a quarter of `[server] max_connections`, so streams never take the connections an administrator needs to sign in; a stream beyond either is refused with 429 `sys.events.too_many_streams`, and the web UI tries again with growing pauses up to 30 seconds.

## 11. Password change required

An account that must change its password (after an administrator reset it) gets 403 `auth.password_change_required` on every route except four: `POST /auth/password`, `POST /auth/password/check`, `POST /auth/logout` and `GET /auth/session`. The check is on the server; the web UI shows the change form first.

## 12. API

Paths are below `/api/v1`. Bodies are JSON. The routes need a session; the listings of grants, subjects, service accounts and role policies also accept a token, and the two routes of a token's own (`/access/token`) take nothing else (a scoped token reads grants and subjects only with a grant that reads users, else 403 `auth.forbidden`). Listing a service account's tokens administers the account, so it needs a session like the other changes.

| Method | Path | Operation id | Success | Notes |
|---|---|---|---|---|
| GET | `/access/grants` | `list_grants` | 200 page of `GrantView` | Every grant for a caller who may read users, else the caller's own grants and those issued under them. `?subject=<user id>` narrows to one holder. Ordered by holder name, then age; not paginated |
| POST | `/access/grants` | `create_grant` | 201 `GrantView`, `Location` | An administrator, or the holder of a delegable grant |
| DELETE | `/access/grants/{id}` | `revoke_grant` | 200 `GrantsRevoked` | Revokes the grants issued under it in the same batch |
| GET | `/access/subjects` | `list_grant_subjects` | 200 page of `SubjectSummary` | The enabled people and service accounts a grant can name, ordered by name; for an administrator or the holder of a delegable grant |
| GET | `/access/service-accounts` | `list_service_accounts` | 200 page of `UserInfo` | Ordered by name |
| POST | `/access/service-accounts` | `create_service_account` | 201 `UserInfo`, `Location` | Administrator; no password, passkey or session |
| GET | `/access/service-accounts/{id}/tokens` | `list_service_account_tokens` | 200 page of `TokenInfo` | Administrator, with a session; secrets are never shown again |
| POST | `/access/service-accounts/{id}/tokens` | `create_service_account_token` | 201 `CreatedToken` | Scoped tokens only; the secret is shown once |
| DELETE | `/access/service-accounts/{id}/tokens/{token}` | `revoke_service_account_token` | 204 | Removes the token's whole family (section 7.1) |
| GET | `/access/token` | `describe_own_token` | 200 `OwnToken` | The calling scoped token, by itself (section 7.3) |
| POST | `/access/token/renew` | `renew_own_token` | 200 `CreatedToken` | The calling token with its renewal secret (section 7.1); never stored for an `Idempotency-Key` |
| GET | `/access/role-policies` | `list_role_policies` | 200 page of `RolePolicyView` | One per role |
| PUT | `/access/role-policies/{role}` | `set_role_policy` | 200 `RolePolicyView` | |
| DELETE | `/access/role-policies/{role}` | `clear_role_policy` | 200 `RolePolicyView` | The role follows the profile again |

Scoped tokens of oneself are created with `POST /auth/tokens` (section 7).

**Create a grant.**

```json
POST /api/v1/access/grants
{
  "subject": "0190d1c2-0000-7000-8000-000000000001",
  "role": "operator",
  "scope": {"kind": "prefix", "value": {"id": "0190d1c2-0000-7000-8000-000000000031", "subtree": true}},
  "delegable": false
}
```

`delegable` defaults to `false`. The answer:

```json
{
  "id": "0190d1c2-0000-7000-8000-000000000041",
  "subject": {"id": "0190d1c2-0000-7000-8000-000000000001", "name": "alice", "display_name": "Alice Example", "kind": "person"},
  "role": "operator",
  "scope": {"kind": "prefix", "value": {"id": "0190d1c2-0000-7000-8000-000000000031", "subtree": true}},
  "delegable": false,
  "granted_by": "0190d1c2-0000-7000-8000-000000000009",
  "granted_at": "2026-10-11T09:00:00Z"
}
```

`parent` appears when a holder of a delegable grant issued it.

**Revoke a grant.**

```json
DELETE /api/v1/access/grants/0190d1c2-0000-7000-8000-000000000041
{"revoked": ["0190d1c2-0000-7000-8000-000000000041", "0190d1c2-0000-7000-8000-000000000042"]}
```

**Set a role policy.**

```json
PUT /api/v1/access/role-policies/viewer
{"mfa": "totp_or_stronger"}
```

```json
{"role": "viewer", "mfa": "totp_or_stronger", "profile_default": "optional", "stored": "totp_or_stronger"}
```

## 13. Error codes

| Code | Status | Meaning |
|---|---|---|
| `auth.forbidden` | 403 | No role or grant allows the action on this kind of object |
| `auth.out_of_scope` | 403 | The object lies outside the scope of the principal |
| `auth.step_up_required` | 403 | The session is weaker than the requirement of the profile, the PIN coupling rule or the role policies; the problem carries `required` |
| `auth.password_change_required` | 403 | The account must change its password first (section 11) |
| `auth.grant.exceeds_own` | 403 | A delegated grant or a token grant goes beyond the grants of its issuer |
| `auth.grant.not_found` | 404 | No such grant, or one the caller does not see |
| `auth.grant.duplicate` | 409 | The subject already holds this role over this scope |
| `auth.grant.invalid_role` | 422 | The role is global-only (`admin`, `auditor`) |
| `auth.grant.invalid_scope` | 422 | The rule cannot be granted (a tenant or object rule) or names an object that does not exist |
| `auth.service_account.not_found` | 404 | No such service account |
| `auth.service_account.no_login` | 409 | A service account has no password, second factor or session |
| `auth.scope.unavailable` | 503 | The server has no IP address management to resolve scopes |
| `auth.token.lifetime_exceeded` | 422 | The lifetime exceeds the maximum of the profile (TGL-05); the problem carries `max_days` |
| `auth.token.not_found` | 404 | No such token |
| `auth.token.limit` | 409 | The owner holds the most scoped tokens it may, 500, superseded ones kept for reuse detection included; the problem carries `max` |
| `auth.token.renewal_refused` | 403 | The token may not renew: `reason` is `disabled` (TGL-46 is off), `not_renewable` (created without the right) or `wrong_secret` (section 7.1) |
| `auth.invalid_request` | 400 | A name, role or lifetime is invalid, or a scoped token has neither grants nor scopes |
| `users.name_taken` | 409 | The service account name is taken |
| `users.last_administrator` | 409 | The only person with the admin role cannot drop it, be disabled or be deleted while only service accounts would remain |
| `users.not_found` | 404 | No such user or service account (on a grant) |
| `auth.unauthenticated` | 401 | No valid session or token, or the account or token is disabled or gone |
| `auth.preference.not_found` | 404 | The person has no preference under this key (section 15) |
| `auth.preference.too_large` | 413 | The document exceeds 16 KiB; the problem carries `max_bytes` |
| `auth.preference.limit` | 409 | A new key would exceed the 64 keys of a person; the problem carries `max_keys` |

## 14. Rollback

Global roles stay in the user record with the meaning they always had. Grants (`auth.grants`), scoped tokens (`auth.scoped_tokens` and the owner index `auth.user_scoped_tokens`) and role policies (`auth.role_policies`) are tables that an older build does not read. After a rollback to such a build, a grant gives nothing and a scoped token is not found, so the person or the automation is refused; nothing is ever read as a global role. Restoring the newer build brings them back unchanged. On a controller that runs a build without self-renewal and source binding (IAM-20, IAM-21), after a rollback or during an upgrade one controller at a time, the renewable and bound tokens (`tnkc_`, section 7.1) stop working: that build accepts `tnk_` tokens only and refuses them before it reads their record, so it never writes one back either. They work again, with their prefixes and renewal state intact, once the controller runs a build that knows them. Plain tokens are unaffected. Such a build lists the superseded and unused tokens of a family as separate tokens and removes only the one named; remove a renewable token on a build that knows families. The rollback rules of the installation are in [upgrades.md](upgrades.md).

## 15. Personal preferences

A person's saved table layouts live on the server, so they follow the person across sessions, browsers and devices (UI-Q4 of [the UI plan](plans/ui-plan.md), API-08). They are the person's own data: the routes take no user id and always act on the user of the request's session, so no role reaches another person's preferences, an administrator's included, and no grant or scope applies. They need an interactive session; a personal or scoped token is refused with `401 auth.unauthenticated`, as on the other routes that act on the person's own account, since the layouts belong to the web UI.

| Method | Path | Operation id | Success | Notes |
|---|---|---|---|---|
| GET | `/auth/preferences` | `list_preferences` | 200 page of `Preference` | Every key of the person, ordered by key; not paginated |
| PUT | `/auth/preferences/{key}` | `put_preference` | 200 `Preference` | The body is a `TableLayout`; creates or replaces the key |
| DELETE | `/auth/preferences/{key}` | `delete_preference` | 204 | The table returns to its default layout ("Reset columns") |

A key is `table:<id>`, the id of a table of the web UI (1 to 64 of `a-z`, `0-9`, `.`, `_` and `-`). The value is a small versioned document:

```json
PUT /api/v1/auth/preferences/table:addresses
{"version": 1, "order": ["ip", "dns_name", "mode", "mac"], "hidden": ["mac"], "widths": {"ip": 140}, "sort": {"column": "ip", "desc": false}}
```

The server checks the shape and the size and nothing else: unknown fields are refused (`400 sys.invalid_request`), the version must be 1, a column id is 1 to 64 of `A-Z`, `a-z`, `0-9`, `.`, `_`, `-` and `:` and appears once per list, each list names at most 128 columns, a width is 16 to 1,200 pixels (`400 auth.invalid_request` naming the field), the document is at most 16 KiB as the canonical JSON the server stores (`413 auth.preference.too_large`), and a person has at most 64 keys (`409 auth.preference.limit`). Which column ids a table has is the web UI's knowledge: it checks a stored layout against the table's known columns and bounds before it applies it, so a crafted document can neither name a column that does not exist nor widen a table beyond its bounds. The document is opaque to the server beyond its schema and never reaches HTML, SQL or a log line.

The rows are in `auth.preferences` by (user, key), replicated with the store and carried by snapshots and backups. Writing a layout is not a change of the installation: nothing is audited and no event reaches the live stream (`auth.preferences` is kept off it). Deleting an account deletes its preferences in the same write. The table is additive, so it needs no new data format ([upgrades.md](upgrades.md) section 4.1): a build before it ignores the table, and a backup taken before it restores with the table empty, which shows every table in its default layout until the person changes it again.
