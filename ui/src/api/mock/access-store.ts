// The state of the access mock (IAM-01, IAM-06, IAM-10): scoped grants and their delegation,
// the MFA policy per role, service accounts and scoped tokens. It lives beside `db` (db.ts
// keeps users, sessions and tokens; the kind and owner of a service account, the grants and
// the policies are kept here). The HTTP side is routes-access.ts; docs/access.md describes
// the behaviour.
//
// The seed after every reset (none for the first-run setup scenarios, which have no users):
//
// - the person "casey" (no global role, a password, no TOTP) with two grants: `operator`
//   over 203.0.113.0/24 and below (prefix `IPAM_IDS.prefix.documentation`, subtree, not
//   delegable, granted by alex) and `viewer` over 198.51.100.0/24 and below
//   (`IPAM_IDS.prefix.iot`, subtree);
// - the service account "dns-sync" (owner alex, no password, no session) with one `viewer`
//   grant over the site `home` and its child sites, and the scoped token "ipam-readonly"
//   (`viewer` over the same site rule, expires in 30 days) in `db.tokens`.
//
// The mock does not enforce scopes on the other routes (see routes-access.ts); it keeps the
// grants, answers the access API and shows the grants in the session, the tokens and the
// strength a role policy asks for.
import type { components } from "../generated/schema";
import type { AuthStrength, RoleName, SecuritySettings, TokenInfo, UserInfo } from "../types";
import { db, onMockReset, toUserInfo, type MockToken, type MockUser } from "./db";
import { MOCK_USER_IDS } from "./fixtures";
import { IPAM_IDS } from "./ipam/seed";
import { ipamState } from "./ipam/state";
import { VrfView } from "./ipam/tree";
import { Problem, fail } from "./reply";
import { DAY_MS, iso, randomId, randomToken, uuidHandle } from "./util";
import { invalid, isRecord, ROLE_NAMES } from "./validate";

type S = components["schemas"];

export type GrantView = S["GrantView"];
export type GrantSubject = S["GrantSubject"];
export type SessionGrant = S["SessionGrant"];
export type ScopeRule = S["ScopeRule"];
export type TokenGrant = S["TokenGrant"];
export type TokenScope = S["TokenScope"];
export type RoleMfa = S["RoleMfa"];

// ---------------------------------------------------------------------------------
// Identifiers and test values

/**
 * The fixed ids of the seed (UUID syntax, group c, numbers from 1001 up; jobs use c0001 to
 * c0006). Other grants, accounts and tokens get random ids.
 */
export const ACCESS_IDS = {
  /** The person "casey". */
  scopedOperator: "0190d1c2-0000-7000-8000-0000000c1001",
  /** Casey's `operator` grant over 203.0.113.0/24 and below. */
  operatorGrant: "0190d1c2-0000-7000-8000-0000000c1002",
  /** Casey's `viewer` grant over 198.51.100.0/24 and below. */
  viewerGrant: "0190d1c2-0000-7000-8000-0000000c1003",
  /** The service account "dns-sync". */
  serviceAccount: "0190d1c2-0000-7000-8000-0000000c1004",
  /** Its `viewer` grant over the site `home` and below. */
  serviceAccountGrant: "0190d1c2-0000-7000-8000-0000000c1005",
  /** Its scoped token "ipam-readonly". */
  serviceToken: "0190d1c2-0000-7000-8000-0000000c1006",
} as const;

/** The person with scoped grants only; a test value like the passwords of fixtures.ts. */
export const SCOPED_OPERATOR = {
  name: "casey",
  password: "lattice-ember-63-harbor",
  display_name: "Casey Example",
} as const;

/** The roles a grant can carry. */
export const GRANTABLE_ROLES: readonly RoleName[] = ["operator", "viewer"];
export const MFA_VALUES: readonly RoleMfa[] = ["optional", "totp_or_stronger", "passkey"];
export const TOKEN_SCOPES: readonly TokenScope[] = ["audit:read", "metrics"];

// ---------------------------------------------------------------------------------
// State

/** A grant as kept: the holder by id, ids and times as text. */
export interface StoredGrant {
  id: string;
  subject: string;
  role: RoleName;
  scope: ScopeRule;
  delegable: boolean;
  granted_by: string | null;
  granted_at: string;
  parent: string | null;
}

export interface AccessState {
  /** In issue order. */
  grants: StoredGrant[];
  /** The stored MFA policy of each role that has one. */
  policies: Map<RoleName, RoleMfa>;
  /** The service accounts by user id, with their owner. */
  accounts: Map<string, { owner: string | null }>;
  /** The grants and special scopes of each scoped token by token id. */
  tokens: Map<string, { grants: TokenGrant[]; scopes: TokenScope[] }>;
}

/** The state. One object for the life of the module: a reset replaces its members. */
export const access: AccessState = { grants: [], policies: new Map(), accounts: new Map(), tokens: new Map() };

/** A problem with a status the catalog of reply.ts does not know the code at. */
export function problem(
  code: string,
  status: number,
  init: { detail?: string; params?: Record<string, string> } = {},
): never {
  throw new Problem(code, { status, ...init });
}

// ---------------------------------------------------------------------------------
// Roles

/** The order of delegation: whether a held role covers the wanted one (docs/access.md section 2). */
export function roleCovers(held: RoleName, wanted: RoleName): boolean {
  if (held === "admin") return true;
  if (held === "operator") return wanted === "operator" || wanted === "viewer";
  return held === wanted;
}

export function rolesCover(held: readonly RoleName[], wanted: RoleName): boolean {
  return held.some((role) => roleCovers(role, wanted));
}

/** Whether the role reads the system (the owner of a `metrics` or `audit:read` token). */
export function readsSystem(roles: readonly RoleName[]): boolean {
  return roles.some((role) => role === "admin" || role === "operator" || role === "viewer" || role === "auditor");
}

/** Whether the roles read the users: the global `admin` and `operator`. */
export function readsUsers(roles: readonly RoleName[]): boolean {
  return roles.includes("admin") || roles.includes("operator");
}

export function grantsOf(userId: string): StoredGrant[] {
  return access.grants.filter((g) => g.subject === userId);
}

/** The roles of a user at any scope: the global roles and the roles of its grants. */
export function rolesHeld(user: { id: string; roles: readonly RoleName[] }): RoleName[] {
  const held = new Set<RoleName>(user.roles);
  for (const grant of grantsOf(user.id)) held.add(grant.role);
  return ROLE_NAMES.filter((role) => held.has(role));
}

export function sessionGrantsOf(userId: string): SessionGrant[] {
  return grantsOf(userId).map((g) => ({ id: g.id, role: g.role, scope: structuredClone(g.scope), delegable: g.delegable }));
}

// ---------------------------------------------------------------------------------
// Role policies (IAM-06)

const MFA_RANK: Readonly<Record<RoleMfa, number>> = { optional: 0, totp_or_stronger: 1, passkey: 2 };

export function stricterMfa(a: RoleMfa, b: RoleMfa): RoleMfa {
  return MFA_RANK[a] >= MFA_RANK[b] ? a : b;
}

/** The requirement of the profile for a role (`default_policy` of the server). */
export function profileDefault(role: RoleName, settings: SecuritySettings): RoleMfa {
  const admin = role === "admin";
  if (admin && settings.passkey_for_admins) return "passkey";
  if (settings.mfa === "everyone" || (settings.mfa === "administrators" && admin)) return "totp_or_stronger";
  return "optional";
}

export function policyView(role: RoleName): S["RolePolicyView"] {
  const stored = access.policies.get(role);
  const base = profileDefault(role, db.settings);
  const view: S["RolePolicyView"] = {
    role,
    mfa: stored === undefined ? base : stricterMfa(stored, base),
    profile_default: base,
  };
  if (stored !== undefined) view.stored = stored;
  return view;
}

/** The strength a stored policy asks for. */
export function policyStrength(mfa: RoleMfa): AuthStrength | null {
  if (mfa === "passkey") return "passkey";
  if (mfa === "totp_or_stronger") return "password_totp";
  return null;
}

/** The strongest strength the stored policies of the roles a user holds ask for, or null. */
export function policyFloor(user: { id: string; roles: readonly RoleName[] }): AuthStrength | null {
  let floor: AuthStrength | null = null;
  for (const role of rolesHeld(user)) {
    const stored = access.policies.get(role);
    const needed = stored === undefined ? null : policyStrength(stored);
    if (needed === "passkey") return "passkey";
    if (needed !== null) floor = needed;
  }
  return floor;
}

// ---------------------------------------------------------------------------------
// Users, service accounts

export function isServiceAccount(id: string): boolean {
  return access.accounts.has(id);
}

/** A user as `UserInfo`: `kind` and `owner` for a service account, none for a person. */
export function userInfoOf(user: MockUser): UserInfo {
  const info = toUserInfo(user);
  const account = access.accounts.get(user.id);
  if (account) {
    info.kind = "service";
    info.owner = account.owner;
  }
  return info;
}

export function subjectOf(user: MockUser): GrantSubject {
  return {
    id: user.id,
    name: user.name,
    display_name: user.display_name,
    kind: access.accounts.has(user.id) ? "service" : "person",
  };
}

/** Removes what the access state holds for a deleted user: grants (and those issued under them), tokens, the account. */
export function forgetUser(userId: string): void {
  const removed = new Set<string>();
  for (const grant of grantsOf(userId)) {
    removed.add(grant.id);
    for (const id of descendants(grant.id)) removed.add(id);
  }
  access.grants = access.grants.filter((g) => !removed.has(g.id));
  for (const token of db.tokens.filter((t) => t.user_id === userId)) access.tokens.delete(token.info.id);
  access.accounts.delete(userId);
}

/** Forgets the grants and special scopes of a token that was revoked. */
export function forgetToken(tokenId: string): void {
  access.tokens.delete(tokenId);
}

// ---------------------------------------------------------------------------------
// Grants

/** Every grant issued under `root`, directly or through further delegation, in issue order. */
export function descendants(root: string): string[] {
  const out: string[] = [];
  const queue = [root];
  const seen = new Set(queue);
  while (queue.length > 0) {
    const next = queue.pop() as string;
    for (const grant of access.grants) {
      if (grant.parent === next && !seen.has(grant.id)) {
        seen.add(grant.id);
        out.push(grant.id);
        queue.push(grant.id);
      }
    }
  }
  return out;
}

/** A grant as the API shows it; a holder that is gone shows with empty names, like the server. */
export function grantViewOf(grant: StoredGrant): GrantView {
  const holder = db.users.find((u) => u.id === grant.subject);
  const view: GrantView = {
    id: grant.id,
    subject: holder
      ? subjectOf(holder)
      : { id: grant.subject, name: "", display_name: "", kind: "person" },
    role: grant.role,
    scope: structuredClone(grant.scope),
    delegable: grant.delegable,
    granted_at: grant.granted_at,
  };
  if (grant.granted_by !== null) view.granted_by = grant.granted_by;
  if (grant.parent !== null) view.parent = grant.parent;
  return view;
}

// ---------------------------------------------------------------------------------
// Scope rules

/**
 * Reads a scope rule of a request body into its canonical shape. A malformed rule fails with
 * `auth.invalid_request`; a rule of a kind that cannot be granted (tenant, object) is
 * returned and refused later with `auth.grant.invalid_scope`.
 */
export function parseScope(value: unknown, field = "scope"): ScopeRule {
  if (!isRecord(value) || typeof value.kind !== "string") return invalid(field, "an object with kind and value is required");
  const v = value.value;
  switch (value.kind) {
    case "vrf":
      if (typeof v !== "string" || v === "") return invalid(field, "the value of a vrf rule is the VRF id");
      return { kind: "vrf", value: v };
    case "tenant":
      if (typeof v !== "string" || v === "") return invalid(field, "the value of a tenant rule is the tenant id");
      return { kind: "tenant", value: v };
    case "site":
    case "prefix": {
      if (!isRecord(v) || typeof v.id !== "string" || v.id === "" || typeof v.subtree !== "boolean") {
        return invalid(field, `the value of a ${value.kind} rule is {id, subtree}`);
      }
      return { kind: value.kind, value: { id: v.id, subtree: v.subtree } };
    }
    case "object":
      if (!isRecord(v) || typeof v.kind !== "string" || typeof v.id !== "string") {
        return invalid(field, "the value of an object rule is {kind, id}");
      }
      return { kind: "object", value: { kind: v.kind, id: v.id } } as ScopeRule;
    default:
      return invalid(field, "the kind of a rule is vrf, site or prefix");
  }
}

export function sameScope(a: ScopeRule, b: ScopeRule): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** The text of a rule for messages: `vrf:<id>`, `site:<id>/subtree`. */
export function describeScope(rule: ScopeRule): string {
  switch (rule.kind) {
    case "vrf":
    case "tenant":
      return `${rule.kind}:${rule.value}`;
    case "site":
    case "prefix":
      return `${rule.kind}:${rule.value.id}${rule.value.subtree ? "/subtree" : ""}`;
    default:
      return `object:${rule.value.id}`;
  }
}

function scopeInvalid(reason: string): never {
  return problem("auth.grant.invalid_scope", 422, { detail: reason, params: { reason } });
}

/** The ids of a site and its ancestors, nearest first; empty for an unknown site. */
function siteChain(id: string): string[] {
  const sites = ipamState().data.site;
  const chain: string[] = [];
  let current = sites.get(id);
  while (current && !current.meta.deleted && !chain.includes(current.id)) {
    chain.push(current.id);
    current = current.parent ? sites.get(current.parent) : undefined;
  }
  return chain;
}

/** The VRF of a prefix and the ids of the prefix and its enclosing prefixes, nearest first. */
function prefixChain(id: string): { vrf: string; chain: string[] } | null {
  const data = ipamState().data;
  const prefix = data.prefix.get(id);
  if (!prefix || prefix.meta.deleted) return null;
  const chain: string[] = [];
  for (let node = new VrfView(data, prefix.vrf).node(id) ?? null; node; node = node.parent) chain.push(node.prefix.id);
  return { vrf: prefix.vrf, chain };
}

/** Checks that a rule can be granted and names a live VRF, site or prefix (422 otherwise). */
export function validateRule(rule: ScopeRule): void {
  const data = ipamState().data;
  switch (rule.kind) {
    case "vrf": {
      const vrf = data.vrf.get(rule.value);
      if (!vrf || vrf.meta.deleted) scopeInvalid(`${describeScope(rule)} does not exist`);
      return;
    }
    case "site": {
      const site = data.site.get(rule.value.id);
      if (!site || site.meta.deleted) scopeInvalid(`${describeScope(rule)} does not exist`);
      return;
    }
    case "prefix":
      if (prefixChain(rule.value.id) === null) scopeInvalid(`${describeScope(rule)} does not exist`);
      return;
    default:
      return scopeInvalid("a grant covers a VRF, a site or a prefix");
  }
}

/**
 * Whether `inner` lies inside `outer` (docs/access.md section 5): the same rule, the same
 * VRF; the same site or prefix when the outer rule has `subtree` or the inner one has none; a
 * site or prefix inside the subtree of an outer site or prefix rule; a prefix in the VRF of
 * an outer VRF rule. Anything else is no.
 */
export function scopeWithin(inner: ScopeRule, outer: ScopeRule): boolean {
  if (sameScope(inner, outer)) return true;
  if (inner.kind === "site" && outer.kind === "site") {
    if (inner.value.id === outer.value.id) return outer.value.subtree || !inner.value.subtree;
    return outer.value.subtree && siteChain(inner.value.id).includes(outer.value.id);
  }
  if (inner.kind === "prefix" && outer.kind === "prefix") {
    if (inner.value.id === outer.value.id) return outer.value.subtree || !inner.value.subtree;
    return outer.value.subtree && (prefixChain(inner.value.id)?.chain.includes(outer.value.id) ?? false);
  }
  if (inner.kind === "prefix" && outer.kind === "vrf") return prefixChain(inner.value.id)?.vrf === outer.value;
  return false;
}

// ---------------------------------------------------------------------------------
// Scoped tokens (IAM-10)

export interface TokenRequest {
  name: string;
  days: number | undefined;
  /** Null when the body has no `grants`. */
  grants: TokenGrant[] | null;
  scopes: TokenScope[];
}

/** Reads the body of `POST /auth/tokens` and `POST /access/service-accounts/{id}/tokens`. */
export function parseTokenRequest(body: Record<string, unknown>): TokenRequest {
  const rawName = body.name;
  if (typeof rawName !== "string") return invalid("name", "a text is required");
  const days = body.expires_in_days;
  if (days !== undefined && days !== null && (typeof days !== "number" || !Number.isInteger(days) || days < 0)) {
    return invalid("expires_in_days", "a whole number of days is required");
  }
  let grants: TokenGrant[] | null = null;
  if (body.grants !== undefined && body.grants !== null) {
    if (!Array.isArray(body.grants)) return invalid("grants", "a list is required");
    grants = body.grants.map((item: unknown) => {
      if (!isRecord(item) || typeof item.role !== "string" || !(ROLE_NAMES as readonly string[]).includes(item.role)) {
        return invalid("grants", "each grant has a role: admin, operator, viewer or auditor");
      }
      const grant: TokenGrant = { role: item.role as RoleName };
      if (item.scope !== undefined && item.scope !== null) grant.scope = parseScope(item.scope, "grants");
      return grant;
    });
  }
  let scopes: TokenScope[] = [];
  if (body.scopes !== undefined && body.scopes !== null) {
    const list = body.scopes;
    if (!Array.isArray(list) || list.some((s) => !(TOKEN_SCOPES as readonly unknown[]).includes(s))) {
      return invalid("scopes", "the special scopes are metrics and audit:read");
    }
    scopes = [...new Set(list as TokenScope[])].sort();
  }
  return { name: rawName, days: typeof days === "number" ? days : undefined, grants, scopes };
}

/** Whether a request asks for a scoped token (`grants` present, or any special scope). */
export function isScopedRequest(request: TokenRequest): boolean {
  return request.grants !== null || request.scopes.length > 0;
}

/**
 * Checks the grants and scopes of a scoped token against its owner (docs/access.md
 * section 7): a global grant needs a global role of the owner that covers it; a scoped one a
 * grantable role, an existing rule, and a global role or a grant of the owner that covers the
 * role over a scope containing the rule; a special scope an owner that is a service account or
 * holds a global role that reads the system.
 */
export function validateTokenGrants(owner: MockUser, request: TokenRequest): TokenGrant[] {
  const exceeds = (): never =>
    problem("auth.grant.exceeds_own", 403, { detail: "the token goes beyond the roles and grants of its owner" });
  const grants: TokenGrant[] = [];
  for (const grant of request.grants ?? []) {
    const global = rolesCover(owner.roles, grant.role);
    if (grant.scope === undefined || grant.scope === null) {
      if (!global) exceeds();
    } else {
      if (!GRANTABLE_ROLES.includes(grant.role)) {
        problem("auth.grant.invalid_role", 422, {
          detail: "admin and auditor are global-only roles",
          params: { role: grant.role },
        });
      }
      validateRule(grant.scope);
      const scope = grant.scope;
      const inside = global || grantsOf(owner.id).some((held) => roleCovers(held.role, grant.role) && scopeWithin(scope, held.scope));
      if (!inside) exceeds();
    }
    if (!grants.some((g) => JSON.stringify(g) === JSON.stringify(grant))) grants.push(grant);
  }
  if (request.scopes.length > 0 && !isServiceAccount(owner.id) && !readsSystem(owner.roles)) exceeds();
  if (grants.length === 0 && request.scopes.length === 0) {
    invalid("grants", "a scoped token needs at least one grant or scope");
  }
  return grants;
}

/** The lifetime of a new token in days under TGL-05, or null for none (422 when over the maximum). */
export function tokenLifetimeDays(days: number | undefined): number | null {
  if (days === 0) return invalid("expires_in_days", "at least one day");
  const max = db.settings.token_max_days ?? null;
  if (days !== undefined && max !== null && days > max) {
    return problem("auth.token.lifetime_exceeded", 422, { params: { max_days: String(max) } });
  }
  return days ?? max;
}

/** The name of a scoped token: visible characters, at most 64. */
function tokenName(raw: string): string {
  const name = raw.trim();
  if (name === "" || /\p{Cc}/u.test(name)) return invalid("name", "visible characters are required");
  return Array.from(name).slice(0, 64).join("");
}

/**
 * Creates a scoped token for `owner`: the checks of the server in its order (name, grants,
 * lifetime), the record in `db.tokens` and the grants and scopes in the access state. The
 * caller commits the change and checks the strength of the session.
 */
export function issueScopedToken(owner: MockUser, request: TokenRequest): { token: string; info: TokenInfo } {
  const name = tokenName(request.name);
  const grants = validateTokenGrants(owner, request);
  const lifetime = tokenLifetimeDays(request.days);
  const secret = `tnk_${randomToken(43)}`;
  const now = Date.now();
  const info: TokenInfo = {
    id: randomId(),
    name,
    prefix: secret.slice(0, 8),
    created_at: iso(now),
    scoped: true,
    grants: structuredClone(grants),
    scopes: [...request.scopes],
  };
  if (lifetime !== null) info.expires_at = iso(now + lifetime * DAY_MS);
  db.tokens.push({ user_id: owner.id, info });
  access.tokens.set(info.id, { grants: structuredClone(grants), scopes: [...request.scopes] });
  return { token: secret, info: { ...info } };
}

// ---------------------------------------------------------------------------------
// The seed

function seedPerson(now: number): MockUser {
  const id = ACCESS_IDS.scopedOperator;
  return {
    id,
    name: SCOPED_OPERATOR.name,
    display_name: SCOPED_OPERATOR.display_name,
    roles: [],
    disabled: false,
    break_glass: false,
    lock: null,
    password: SCOPED_OPERATOR.password,
    totp: false,
    credentials: [],
    recovery_codes: [],
    password_change_required: false,
    language: null,
    created_at: iso(now - 20 * DAY_MS),
    last_login_at: null,
    revision: db.revision,
    handle: uuidHandle(id),
  };
}

function seedServiceAccount(now: number): MockUser {
  const id = ACCESS_IDS.serviceAccount;
  return {
    id,
    name: "dns-sync",
    display_name: "DNS sync",
    roles: [],
    disabled: false,
    break_glass: false,
    lock: null,
    password: null,
    totp: false,
    credentials: [],
    recovery_codes: [],
    password_change_required: false,
    language: null,
    created_at: iso(now - 12 * DAY_MS),
    last_login_at: null,
    revision: db.revision,
    handle: uuidHandle(id),
  };
}

/**
 * Whether every reset seeds casey and dns-sync. On in the browser mock (npm run dev:mock), so a
 * scoped operator can sign in; off under the unit tests, whose user and token lists predate the
 * seed: a test that needs it calls `seedAccess()` after `resetMockDb`.
 */
const AUTO_SEED = import.meta.env.MODE !== "test";

function clearAccess(): void {
  access.grants = [];
  access.policies = new Map();
  access.accounts = new Map();
  access.tokens = new Map();
}

/** Adds the scoped operator casey and the service account dns-sync with their grants and token. */
export function seedAccess(): void {
  clearAccess();
  // No users, no access data: the first-run setup scenarios.
  if (db.users.length === 0) return;

  const now = Date.now();
  const alex = MOCK_USER_IDS.alex;
  const siteRule: ScopeRule = { kind: "site", value: { id: IPAM_IDS.site.home, subtree: true } };
  if (!db.users.some((u) => u.id === ACCESS_IDS.scopedOperator)) db.users.push(seedPerson(now));
  if (!db.users.some((u) => u.id === ACCESS_IDS.serviceAccount)) db.users.push(seedServiceAccount(now));
  access.accounts.set(ACCESS_IDS.serviceAccount, { owner: alex });
  access.grants.push(
    {
      id: ACCESS_IDS.operatorGrant,
      subject: ACCESS_IDS.scopedOperator,
      role: "operator",
      scope: { kind: "prefix", value: { id: IPAM_IDS.prefix.documentation, subtree: true } },
      delegable: false,
      granted_by: alex,
      granted_at: iso(now - 14 * DAY_MS),
      parent: null,
    },
    {
      id: ACCESS_IDS.viewerGrant,
      subject: ACCESS_IDS.scopedOperator,
      role: "viewer",
      scope: { kind: "prefix", value: { id: IPAM_IDS.prefix.iot, subtree: true } },
      delegable: false,
      granted_by: alex,
      granted_at: iso(now - 13 * DAY_MS),
      parent: null,
    },
    {
      id: ACCESS_IDS.serviceAccountGrant,
      subject: ACCESS_IDS.serviceAccount,
      role: "viewer",
      scope: structuredClone(siteRule),
      delegable: false,
      granted_by: alex,
      granted_at: iso(now - 12 * DAY_MS),
      parent: null,
    },
  );
  const token: MockToken = {
    user_id: ACCESS_IDS.serviceAccount,
    info: {
      id: ACCESS_IDS.serviceToken,
      name: "ipam-readonly",
      prefix: "tnk_ab12",
      created_at: iso(now - 10 * DAY_MS),
      expires_at: iso(now + 30 * DAY_MS),
      scoped: true,
      grants: [{ role: "viewer", scope: structuredClone(siteRule) }],
      scopes: [],
    },
  };
  db.tokens.push(token);
  access.tokens.set(token.info.id, { grants: structuredClone(token.info.grants ?? []), scopes: [] });
}

function reset(): void {
  if (AUTO_SEED) seedAccess();
  else clearAccess();
}

// `db` was replaced before the reset listeners run, so `db.users` is fresh here.
onMockReset(reset);
reset();

/** Fails with `auth.forbidden`; used where an access route needs a global role. */
export function forbidden(detail: string): never {
  return fail("auth.forbidden", { detail });
}

