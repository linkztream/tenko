// Mock routes of the `access` API area (OpenAPI tag `access`): scoped grants and their
// delegation, service accounts and their scoped tokens, and the MFA policy per role (IAM-01,
// IAM-06, IAM-10), after crates/tenko-auth/src/service/access.rs and docs/access.md. The state
// is access-store.ts.
//
// Who may do what, as on the server: an administrator does everything. A person with a
// global `operator` role reads users, so reads every grant, the subjects, the service accounts
// and the role policies. A holder of a delegable grant creates and revokes grants inside its
// own (and lists the subjects). Everybody else gets their own grants and the grants issued
// under them, or 403 `auth.forbidden`.
//
// What the mock leaves out: it does not audit (the other admin routes of the mock do not
// either), it does not enforce grants or scopes on the other routes (a scoped person sees
// everything their global roles allow), and a token authenticates nobody (the mock has no
// bearer authentication), so the intersection of a token and its owner is not computed.
import type { HttpHandler } from "msw";
import type { RoleName } from "../types";
import {
  GRANTABLE_ROLES,
  MFA_VALUES,
  access,
  descendants,
  grantViewOf,
  grantsOf,
  isServiceAccount,
  isScopedRequest,
  issueScopedToken,
  parseScope,
  parseTokenRequest,
  policyView,
  problem,
  readsUsers,
  roleCovers,
  sameScope,
  scopeWithin,
  subjectOf,
  userInfoOf,
  validateRule,
  type RoleMfa,
  type StoredGrant,
} from "./access-store";
import { requireAdmin, requireSession, requireStrength } from "./auth";
import { commit, db, findUser, findUserByName, isAdmin, userChange, type MockUser } from "./db";
import { created, fail, noContent, ok } from "./reply";
import { paginate, route, wholePage } from "./route";
import { iso, isUuid, randomId, uuidHandle } from "./util";
import {
  invalid,
  oneOf,
  optBool,
  optString,
  reqString,
  ROLE_NAMES,
  validDisplayName,
  validUserName,
} from "./validate";

const API = "/api/v1";

function byName<T extends { name: string }>(items: T[]): T[] {
  return items.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

/** A caller that is not an administrator must be a person with a session that is strong enough (`delegating_user`). */
function delegator(): { user: MockUser; admin: boolean } {
  const { session, user } = requireSession();
  const admin = isAdmin(user);
  if (!admin) requireStrength(session, user);
  return { user, admin };
}

function grantChange(grant: StoredGrant) {
  return {
    objects: [
      { kind: "grant", id: grant.id },
      { kind: "user", id: grant.subject },
    ],
    tables: ["auth.grants"],
  };
}

// ---------------------------------------------------------------------------------
// Grants

const listGrants = route("get", "/api/v1/access/grants", (ctx) => {
  const { user } = requireSession();
  const subject = ctx.query("subject");
  if (subject !== null && !isUuid(subject)) {
    return fail("sys.invalid_query", { params: { name: "subject", value: subject } });
  }
  let visible: StoredGrant[];
  if (readsUsers(user.roles)) {
    visible = access.grants;
  } else {
    const ids = new Set<string>();
    for (const own of grantsOf(user.id)) {
      ids.add(own.id);
      for (const id of descendants(own.id)) ids.add(id);
    }
    visible = access.grants.filter((g) => ids.has(g.id));
  }
  const views = visible
    .filter((g) => subject === null || g.subject === subject)
    .map(grantViewOf)
    .sort(
      (a, b) =>
        a.subject.name.toLowerCase().localeCompare(b.subject.name.toLowerCase()) ||
        a.granted_at.localeCompare(b.granted_at) ||
        a.id.localeCompare(b.id),
    );
  return ok(wholePage(views, db.revision));
});

const createGrant = route("post", "/api/v1/access/grants", async (ctx) => {
  const { user: caller, admin } = delegator();
  const body = await ctx.body();
  const subjectId = reqString(body, "subject");
  const role = oneOf<RoleName>(body.role, ROLE_NAMES, "role");
  const scope = parseScope(body.scope);
  const delegable = optBool(body, "delegable") ?? false;

  if (!GRANTABLE_ROLES.includes(role)) {
    return problem("auth.grant.invalid_role", 422, {
      detail: "admin and auditor are global-only roles and cannot be granted",
      params: { role },
    });
  }
  const subject = isUuid(subjectId) ? findUser(subjectId) : undefined;
  if (!subject) return fail("users.not_found", { params: { kind: "user" } });
  if (subject.break_glass) invalid("subject", "the break-glass account holds the admin role only");
  validateRule(scope);
  if (access.grants.some((g) => g.subject === subject.id && g.role === role && sameScope(g.scope, scope))) {
    return problem("auth.grant.duplicate", 409, { detail: "the subject holds this role over this scope already" });
  }
  let parent: string | null = null;
  if (!admin) {
    const under = grantsOf(caller.id).find((g) => g.delegable && roleCovers(g.role, role) && scopeWithin(scope, g.scope));
    if (!under) {
      return problem("auth.grant.exceeds_own", 403, {
        detail: "a delegated grant stays inside the delegable grants of its issuer",
      });
    }
    parent = under.id;
  }
  const grant: StoredGrant = {
    id: randomId(),
    subject: subject.id,
    role,
    scope,
    delegable,
    granted_by: caller.id,
    granted_at: iso(Date.now()),
    parent,
  };
  access.grants.push(grant);
  commit("admin", grantChange(grant));
  return created(grantViewOf(grant), { Location: `${API}/access/grants/${grant.id}` });
});

const revokeGrant = route("delete", "/api/v1/access/grants/{id}", (ctx) => {
  const { user: caller, admin } = delegator();
  const id = ctx.params.id;
  const target = access.grants.find((g) => g.id === id);
  const notFound = () => problem("auth.grant.not_found", 404, { params: { kind: "grant" } });
  if (!target) return notFound();
  if (!admin) {
    const reachable = grantsOf(caller.id).some((own) => own.id === id || descendants(own.id).includes(id));
    if (!reachable) return notFound();
  }
  const revoked = [id, ...descendants(id)];
  const gone = new Set(revoked);
  const holders = new Set(access.grants.filter((g) => gone.has(g.id)).map((g) => g.subject));
  access.grants = access.grants.filter((g) => !gone.has(g.id));
  commit("admin", {
    deleted: revoked.map((grant) => ({ kind: "grant", id: grant })),
    objects: [...holders].map((holder) => ({ kind: "user", id: holder })),
    tables: ["auth.grants"],
  });
  return ok({ revoked });
});

const listGrantSubjects = route("get", "/api/v1/access/subjects", (ctx) => {
  const { user } = requireSession();
  if (!readsUsers(user.roles) && !grantsOf(user.id).some((g) => g.delegable)) {
    return fail("auth.forbidden", { detail: "this needs the right to read users or a delegable grant" });
  }
  const subjects = db.users.filter((u) => !u.break_glass && !u.disabled).map(subjectOf);
  return ok(paginate(byName(subjects), ctx.url, db.revision));
});

// ---------------------------------------------------------------------------------
// Service accounts and their tokens

const SA_NOT_FOUND = "auth.service_account.not_found";

function serviceAccountOr404(id: string): MockUser {
  const account = isUuid(id) ? findUser(id) : undefined;
  if (!account || !isServiceAccount(account.id)) {
    return problem(SA_NOT_FOUND, 404, { params: { kind: "service_account" } });
  }
  return account;
}

const listServiceAccounts = route("get", "/api/v1/access/service-accounts", (ctx) => {
  const { user } = requireSession();
  if (!readsUsers(user.roles)) return fail("auth.forbidden", { detail: "this needs the right to read users" });
  const accounts = db.users.filter((u) => isServiceAccount(u.id));
  const sorted = byName([...accounts]).map((u) => userInfoOf(u));
  return ok(paginate(sorted, ctx.url, db.revision));
});

/** The global roles of a service account: known roles, no duplicates; an empty list is fine. */
function accountRoles(value: unknown): RoleName[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return invalid("roles", "a list of roles is required");
  for (const role of value) {
    if (typeof role !== "string" || !(ROLE_NAMES as readonly string[]).includes(role)) {
      return invalid("roles", `unknown role ${JSON.stringify(role)}`);
    }
  }
  return ROLE_NAMES.filter((r) => value.includes(r));
}

const createServiceAccount = route("post", "/api/v1/access/service-accounts", async (ctx) => {
  const { user: admin } = requireAdmin();
  const body = await ctx.body();
  const name = validUserName(reqString(body, "name"));
  const displayName = validDisplayName(optString(body, "display_name"), name);
  const roles = accountRoles(body.roles);
  if (findUserByName(name)) return fail("users.name_taken", { params: { name } });

  const id = randomId();
  const account: MockUser = {
    id,
    name,
    display_name: displayName,
    roles,
    disabled: false,
    break_glass: false,
    lock: null,
    // No password, passkey, second factor or session.
    password: null,
    totp: false,
    credentials: [],
    recovery_codes: [],
    password_change_required: false,
    language: null,
    created_at: iso(Date.now()),
    last_login_at: null,
    revision: db.revision,
    handle: uuidHandle(id),
  };
  db.users.push(account);
  access.accounts.set(id, { owner: admin.id });
  commit("admin", userChange(account), [account]);
  return created(userInfoOf(account), { Location: `${API}/users/${id}`, ETag: `"${account.revision}"` });
});

const listServiceAccountTokens = route("get", "/api/v1/access/service-accounts/{id}/tokens", (ctx) => {
  requireAdmin();
  const account = serviceAccountOr404(ctx.params.id);
  const tokens = db.tokens
    .filter((t) => t.user_id === account.id)
    .map((t) => ({ ...t.info }))
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  return ok(paginate(tokens, ctx.url, db.revision));
});

const createServiceAccountToken = route("post", "/api/v1/access/service-accounts/{id}/tokens", async (ctx) => {
  const { session, user: admin } = requireAdmin();
  const account = serviceAccountOr404(ctx.params.id);
  requireStrength(session, admin);
  const request = parseTokenRequest(await ctx.body());
  // A service account has scoped tokens only; a body with neither grants nor scopes is not a token request.
  if (!isScopedRequest(request)) invalid("grants", "a scoped token needs at least one grant or scope");
  const issued = issueScopedToken(account, request);
  commit("admin", {
    objects: [
      { kind: "token", id: issued.info.id },
      { kind: "user", id: account.id },
    ],
    tables: ["auth.scoped_tokens", "auth.user_scoped_tokens"],
  });
  return created(issued);
});

const revokeServiceAccountToken = route("delete", "/api/v1/access/service-accounts/{id}/tokens/{token}", (ctx) => {
  requireAdmin();
  const account = serviceAccountOr404(ctx.params.id);
  const index = db.tokens.findIndex((t) => t.user_id === account.id && t.info.id === ctx.params.token);
  if (index < 0) return fail("auth.token.not_found");
  db.tokens.splice(index, 1);
  access.tokens.delete(ctx.params.token);
  commit("admin", {
    deleted: [{ kind: "token", id: ctx.params.token }],
    objects: [{ kind: "user", id: account.id }],
    tables: ["auth.scoped_tokens", "auth.user_scoped_tokens"],
  });
  return noContent();
});

// ---------------------------------------------------------------------------------
// Role policies

function roleParam(raw: string): RoleName {
  return oneOf<RoleName>(raw, ROLE_NAMES, "role");
}

const listRolePolicies = route("get", "/api/v1/access/role-policies", () => {
  const { user } = requireSession();
  if (!readsUsers(user.roles)) return fail("auth.forbidden", { detail: "this needs the right to read settings" });
  return ok(wholePage(ROLE_NAMES.map(policyView), db.revision));
});

const setRolePolicy = route("put", "/api/v1/access/role-policies/{role}", async (ctx) => {
  requireAdmin();
  const role = roleParam(ctx.params.role);
  const mfa = oneOf<RoleMfa>((await ctx.body()).mfa, MFA_VALUES, "mfa");
  if (access.policies.get(role) !== mfa) {
    access.policies.set(role, mfa);
    commit("admin", { tables: ["auth.role_policies"], objects: [{ kind: "role_policy", id: role }] });
  }
  return ok(policyView(role));
});

const clearRolePolicy = route("delete", "/api/v1/access/role-policies/{role}", (ctx) => {
  requireAdmin();
  const role = roleParam(ctx.params.role);
  if (access.policies.delete(role)) {
    commit("admin", { tables: ["auth.role_policies"], objects: [{ kind: "role_policy", id: role }] });
  }
  return ok(policyView(role));
});

export const accessRoutes: HttpHandler[] = [
  listGrants,
  createGrant,
  revokeGrant,
  listGrantSubjects,
  listServiceAccounts,
  createServiceAccount,
  listServiceAccountTokens,
  createServiceAccountToken,
  revokeServiceAccountToken,
  listRolePolicies,
  setRolePolicy,
  clearRolePolicy,
];
