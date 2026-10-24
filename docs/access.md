# Access: roles, scoped grants, service accounts and scoped tokens

This page describes who may do what in Tenko DDI: the four roles, scoped grants over VRFs, sites and prefixes, delegation, service accounts, scoped API tokens, the multi-factor policy per role, and what a scoped person sees in lists, the prefix tree, search, exports, the audit log and the event stream. It is for an administrator who gives people and automation limited access, and for a developer who adds a route and has to decide how it is scoped. It describes the behaviour of `tenko-auth` (`authz`, `roles`, `grants`, `service/access`), of the anchors index in `tenko-ipam` (`scope`), and of the `/access` routes and the scoped filters in `tenko-api`; where this page and the code differ, the code is right. The requirements are IAM-01, IAM-06 and IAM-10 in [REQUIREMENTS.md](REQUIREMENTS.md); the profile values are TGL-02, TGL-03 and TGL-05 in [SECURITY-PROFILES.md](SECURITY-PROFILES.md). The decisions are recorded in [ADR 0015](adr/0015-scoped-authorization.md).

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
| `auditor` | Reads the audit log, the audit export status and the system status. Nothing else (section 9). | Globally only |

A grant carries `operator` or `viewer`. A grant reaches only the kinds that scopes apply to: tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, custom fields, jobs, observations and proposals. The other kinds are global-only in Phase 1: imports, connectors, nodes, secrets, settings, users, sessions, tokens and the system. A person who holds only grants therefore cannot run an import, change a connector, read a secret or manage users, whatever the grant says.

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

Rules for tenants and for single objects exist in the data model but cannot be granted in Phase 1 (422 `auth.grant.invalid_scope`). Zones and DHCP scopes join in Phases 2 and 3.

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
| Observation, proposal | The chain of the prefix of the subject address, merged with the objects the proposal names |
| Job | The anchors of its targets, merged |

### 3.3 Read any, write all

- **Read.** An object is readable when one of its anchors is covered by a rule of a grant whose role allows the read. A host with addresses in two prefixes is readable when the principal holds one of them.
- **Create, update, delete.** Every anchor of the object must be covered, and the object must lie inside the scope both where it is and where it goes. A host with addresses in two prefixes can be changed only by a principal that holds both, or holds a rule that covers the host whole (its VRF or its site). A prefix rule never admits a write to a host that has an address outside the rule. An object that has a part with no prefix chain at all carries an empty chain and so needs a rule that covers it whole.

Writes are planned first. A scoped principal's change is planned as for anybody, and every planned change is checked before and after it is applied: a prefix cannot be moved out of or into a scope the principal does not hold, and an interface or an address bound to a host needs the right to change that host before and after. A refused plan changes nothing and answers 403 `auth.out_of_scope`.

### 3.4 Context kinds

Every principal with a grant may read tenants, VRFs, sites and custom field definitions, whatever the rule covers, so that names and forms can be shown. Changing them still needs a rule that covers them.

### 3.5 Global-only kinds and the two special objects

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

Revoking a grant revokes every grant issued under it, directly or through further delegation, in the same batch. The answer lists them. Deleting an account removes its grants and the grants issued under them.

Only people with a session create or revoke grants. A token never does, whatever its grants. A refused delegation is audited as a failed `auth.grant.create`. Every change is audited: `auth.grant.create` names the subject, the grant, the role, the scope, `delegable` and the parent; `auth.grant.revoke` names the subjects, the grant, the scope and every revoked grant.

An administrator (a caller who may administer users) grants any scope to anybody and has no parent. A person who is neither an administrator nor the holder of a delegable grant gets 403 `auth.forbidden` or `auth.grant.exceeds_own`.

## 6. Service accounts

A service account is an account for automation (IAM-10). It differs from a person in these ways.

- It has no password, passkey, second factor or session. A sign-in with its name fails like a sign-in with an unknown account. Setting a password on it is refused with 409 `auth.service_account.no_login`.
- An administrator creates it and is recorded as its owner. Its name shares the name space of users (409 `users.name_taken`).
- It holds global roles (`roles` at creation) or grants, like a person. A service account can receive any grant a person can.
- It acts only through scoped tokens (section 7). A personal token of a service account is refused.

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

**Special scopes.** `metrics` lets the token read the metrics endpoint; `audit:read` lets it read the audit log. Both read only: the token reaches nothing else through them; its lists of the other kinds are empty and their single reads are refused with 403 `auth.forbidden` (section 1). An owner may ask for a special scope if it is a service account or holds a global role that reads the system. A token needs at least one grant or one scope.

**Intersection.** The effective right of a request is the intersection of the token's grants and the owner's grants at that moment. An object must be covered by the token's rules and by the owner's rules. A token therefore loses rights when its owner loses them, is refused when the owner is disabled or deleted (the scoped tokens of a deleted account are removed), and never gains rights its owner gains later. A token cannot administer: changing users, settings, the system, tokens, sessions or secrets, revealing a secret, and every administrative action need an interactive session.

**Lifetime.** `expires_in_days` defaults to the maximum of the profile (TGL-05: 365 days in Home, 90 in Standard, 30 in Hardened, no maximum in Lab) and may not exceed it (422 `auth.token.lifetime_exceeded`). The cap is checked again at every use against the creation time of the token, so tightening it shortens the tokens that exist.

**Creating.** A person creates a scoped token for themselves with `POST /auth/tokens` and `grants` or `scopes` in the body; without them the call creates a personal token. An administrator creates one for a service account with `POST /access/service-accounts/{id}/tokens`. The session that creates a token must meet the strength required of its user. The secret (`tnk_...`) is shown once; the listing shows the first characters only.

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

The policies are read with `GET /access/role-policies`, which lists the four roles with the requirement in force (`mfa`), the profile's (`profile_default`) and the stored policy (`stored`, absent when the role follows the profile). `PUT /access/role-policies/{role}` stores a value and `DELETE` makes the role follow the profile again. Both need the right to change settings and a strong enough session, and are audited as `auth.role_policy.update` with the old and new value.

## 9. The auditor

The `auditor` role is global-only and cannot be granted. It reads the audit log, the audit export status and the system status. It cannot read the inventory, users, settings, secrets, nodes or imports, and it cannot change anything. A viewer, by contrast, also reads the audit log through the system kind, so an installation that wants the trail read by somebody who does not see the inventory gives them the auditor role and no other.

The auditor reads `GET /audit`, `GET /audit/{seq}` and `GET /audit/verify`. A token with the scope `audit:read` reads the same audit routes.

## 10. What scoped principals see

A principal whose reach is scoped receives only what its rules cover. Lists filter before paging, so a page is full whenever more matching objects exist, and the cursor and the revision behave as for anybody.

| Route | Behaviour |
|---|---|
| Lists (tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts, interfaces, custom fields, observations, proposals, jobs, topology) | Only objects in scope; tenants, VRFs, sites and custom fields as context |
| Lists of a kind the principal reaches nothing of | `200` with no items, never 403 (section 1) |
| Single reads and history | 403 `auth.out_of_scope` outside the scope |
| Prefix tree | The prefixes in scope as nodes; see below |
| Search | Only hits in scope |
| Exports (`/exports/*.csv`) | Only objects in scope |
| Audit log | See below |
| Proposals | Listed by the prefix of the subject address; an approval is planned and checked against the scope before it applies |
| Jobs | Listed and read when one of the targets is in scope; cancelled or completed when all targets are |
| Moves | Update on every moved object and on the target prefix; a preview needs Read on them |
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

**Audit log.** A principal that may read the audit log (a global role that reads the system, the auditor, a token with `audit:read`) sees every record. A principal that does not, but whose grants reach IPAM objects, sees only the records that name at least one object and all of whose objects are of a scoped kind inside its scope. `GET /audit/verify` needs the global permission.

**Events.** The event stream carries references, never bodies. For a scoped principal the server drops the references to objects outside the scope, keeps tenants, VRFs, sites and custom field definitions, and drops table-level events (an event with no reference) of topics the principal cannot read: IPAM, jobs and discovery pass for any grant that reaches them; audit, import, system, admin, connectors, secrets, cluster and metrics need a global read, or the token scope of the metrics and audit objects. A frame left with no reference is not sent.

## 11. Password change required

An account that must change its password (after an administrator reset it) gets 403 `auth.password_change_required` on every route except four: `POST /auth/password`, `POST /auth/password/check`, `POST /auth/logout` and `GET /auth/session`. The check is on the server; the web UI shows the change form first.

## 12. API

Paths are below `/api/v1`. Bodies are JSON. The routes need a session; the listings of grants, subjects, service accounts and role policies also accept a token. Listing a service account's tokens administers the account, so it needs a session like the other changes.

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
| DELETE | `/access/service-accounts/{id}/tokens/{token}` | `revoke_service_account_token` | 204 | |
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
| `auth.invalid_request` | 400 | A name, role or lifetime is invalid, or a scoped token has neither grants nor scopes |
| `users.name_taken` | 409 | The service account name is taken |
| `users.not_found` | 404 | No such user or service account (on a grant) |
| `auth.unauthenticated` | 401 | No valid session or token, or the account or token is disabled or gone |

## 14. Rollback

Global roles stay in the user record with the meaning they always had. Grants (`auth.grants`), scoped tokens (`auth.scoped_tokens` and the owner index `auth.user_scoped_tokens`) and role policies (`auth.role_policies`) are tables that an older build does not read. After a rollback to such a build, a grant gives nothing and a scoped token is not found, so the person or the automation is refused; nothing is ever read as a global role. Restoring the newer build brings them back unchanged. The rollback rules of the installation are in [upgrades.md](upgrades.md).
