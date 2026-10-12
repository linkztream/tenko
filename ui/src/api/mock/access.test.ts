// The access mock through `fetch`, against the msw server that src/app/testing/setup.ts
// starts: the seed, grants and their delegation, service accounts and scoped tokens, the MFA
// policy per role and the scoped personal tokens (docs/access.md).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import type { CreatedToken, LoginResponse, Page, SessionInfo, TokenInfo, UserInfo } from "../types";
import { ACCESS_IDS, SCOPED_OPERATOR, access, seedAccess } from "./access-store";
import { startSession } from "./auth";
import { db, findUserByName, resetMockDb } from "./db";
import { MOCK_PASSWORDS, MOCK_USER_IDS } from "./fixtures";
import { IPAM_IDS } from "./ipam/seed";

type S = components["schemas"];
type GrantView = S["GrantView"];
type RolePolicyView = S["RolePolicyView"];

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

interface CallInit {
  json?: unknown;
  headers?: Record<string, string>;
}

async function call<T = unknown>(method: string, path: string, init: CallInit = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json === undefined ? null : JSON.stringify(init.json) });
  const text = await res.text();
  const json = (res.headers.get("content-type") ?? "").includes("json");
  return { res, status: res.status, body: (text && json ? JSON.parse(text) : text || undefined) as T };
}

const get = <T>(path: string, init?: CallInit) => call<T>("GET", path, init);
const post = <T>(path: string, json?: unknown, init: CallInit = {}) => call<T>("POST", path, { ...init, json });
const patch = <T>(path: string, json: unknown, init: CallInit = {}) => call<T>("PATCH", path, { ...init, json });
const put = <T>(path: string, json: unknown, init: CallInit = {}) => call<T>("PUT", path, { ...init, json });
const del = <T>(path: string, init?: CallInit) => call<T>("DELETE", path, init);

interface Problem {
  status: number;
  code: string;
  detail: string;
  params: Record<string, string>;
}

function expectProblem(answer: Answer<unknown>, status: number, code: string): Problem {
  expect(answer.status).toBe(status);
  expect(answer.res.headers.get("content-type")).toContain("application/problem+json");
  const body = answer.body as Problem;
  expect(body.code).toBe(code);
  expect(body.status).toBe(status);
  expect(typeof body.detail).toBe("string");
  expect(body.params).toBeTypeOf("object");
  return body;
}

const V = "/api/v1";
const ALEX = MOCK_USER_IDS.alex;
const CASEY = ACCESS_IDS.scopedOperator;

const prefixRule = (id: string, subtree = true) => ({ kind: "prefix", value: { id, subtree } });
const siteRule = (id: string, subtree = true) => ({ kind: "site", value: { id, subtree } });

/** Signs a seed user in without the login ceremony (alex needs a second factor there). */
function signInAs(name: string, strength: Parameters<typeof startSession>[1] = "passkey"): void {
  const user = findUserByName(name);
  if (!user) throw new Error(`no user ${name}`);
  user.disabled = false;
  startSession(user, strength);
}

async function loginAsCasey(): Promise<SessionInfo> {
  const answer = await post<LoginResponse>(`${V}/auth/login/password`, {
    user_name: SCOPED_OPERATOR.name,
    password: SCOPED_OPERATOR.password,
  });
  expect(answer.status).toBe(200);
  if (answer.body.status !== "authenticated") throw new Error("a second factor is required");
  return answer.body.session;
}

async function grantsOf(query = ""): Promise<GrantView[]> {
  const answer = await get<Page<GrantView>>(`${V}/access/grants${query}`);
  expect(answer.status).toBe(200);
  return answer.body.items;
}

async function createGrant(body: unknown): Promise<Answer<GrantView>> {
  return post<GrantView>(`${V}/access/grants`, body);
}

beforeEach(() => {
  resetMockDb("signed-in");
  seedAccess();
});

// ---------------------------------------------------------------------------------
// The seed

describe("the seed", () => {
  it("has casey with two grants, a service account with a grant and a scoped token", async () => {
    const grants = await grantsOf();
    expect(grants.map((g) => [g.subject.name, g.role, g.scope])).toEqual([
      ["casey", "operator", prefixRule(IPAM_IDS.prefix.documentation)],
      ["casey", "viewer", prefixRule(IPAM_IDS.prefix.iot)],
      ["dns-sync", "viewer", siteRule(IPAM_IDS.site.home)],
    ]);
    const operator = grants[0] as GrantView;
    expect(operator).toMatchObject({
      id: ACCESS_IDS.operatorGrant,
      delegable: false,
      granted_by: ALEX,
      subject: { id: CASEY, display_name: SCOPED_OPERATOR.display_name, kind: "person" },
    });
    expect(operator.parent).toBeUndefined();
    expect(grants[1]?.id).toBe(ACCESS_IDS.viewerGrant);
    expect(grants[2]?.subject.kind).toBe("service");

    const casey = findUserByName("casey");
    expect(casey).toMatchObject({ id: CASEY, roles: [], password: SCOPED_OPERATOR.password, totp: false, disabled: false });
  });

  it("lists the service account with its kind and owner, among the users as GET /users does", async () => {
    const users = await get<Page<UserInfo>>(`${V}/users`);
    expect(users.body.items.map((u) => u.name)).toEqual(["alex", "breakglass", "casey", "dns-sync", "robin", "sam"]);
    const casey = users.body.items.find((u) => u.name === "casey") as UserInfo;
    expect(casey.kind).toBeUndefined();
    expect(casey.owner).toBeUndefined();
    const account = users.body.items.find((u) => u.name === "dns-sync") as UserInfo;
    expect(account).toMatchObject({
      id: ACCESS_IDS.serviceAccount,
      kind: "service",
      owner: ALEX,
      display_name: "DNS sync",
      roles: [],
      factors: { password: false, totp: false, webauthn: 0 },
    });

    const accounts = await get<Page<UserInfo>>(`${V}/access/service-accounts`);
    expect(accounts.body.items.map((u) => u.name)).toEqual(["dns-sync"]);

    const tokens = await get<Page<TokenInfo>>(`${V}/access/service-accounts/${ACCESS_IDS.serviceAccount}/tokens`);
    expect(tokens.body.items).toHaveLength(1);
    expect(tokens.body.items[0]).toMatchObject({
      id: ACCESS_IDS.serviceToken,
      name: "ipam-readonly",
      prefix: "tnk_ab12",
      scoped: true,
      grants: [{ role: "viewer", scope: siteRule(IPAM_IDS.site.home) }],
      scopes: [],
    });
    const days = (Date.parse(tokens.body.items[0]?.expires_at as string) - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(30);
  });

  it("is seeded in every scenario but setup, and only on request under the unit tests", () => {
    resetMockDb("signed-in");
    expect(findUserByName("casey")).toBeUndefined();
    expect(access.grants).toHaveLength(0);
    for (const scenario of ["signed-out", "lab", "weak"] as const) {
      resetMockDb(scenario);
      seedAccess();
      expect(findUserByName("casey")?.id).toBe(CASEY);
      expect(access.grants).toHaveLength(3);
      expect(db.tokens.some((t) => t.info.id === ACCESS_IDS.serviceToken)).toBe(true);
    }
    for (const scenario of ["setup", "setup-slow-disk"] as const) {
      resetMockDb(scenario);
      seedAccess();
      expect(db.users).toHaveLength(0);
      expect(access.grants).toHaveLength(0);
      expect(db.tokens).toHaveLength(0);
    }
  });

  it("shows the grants of casey in the session", async () => {
    const session = await loginAsCasey();
    expect(session.roles).toEqual([]);
    expect(session.grants).toEqual([
      { id: ACCESS_IDS.operatorGrant, role: "operator", scope: prefixRule(IPAM_IDS.prefix.documentation), delegable: false },
      { id: ACCESS_IDS.viewerGrant, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.iot), delegable: false },
    ]);
    const again = await get<SessionInfo>(`${V}/auth/session`);
    expect(again.body.grants).toHaveLength(2);

    // A person without grants has no `grants` member.
    signInAs("sam");
    expect((await get<SessionInfo>(`${V}/auth/session`)).body.grants).toBeUndefined();
  });

  it("does not let a service account sign in or get a password", async () => {
    const login = await post(`${V}/auth/login/password`, { user_name: "dns-sync", password: "anything-at-all-123" });
    expectProblem(login, 401, "auth.invalid_credentials");
    const unknown = await post(`${V}/auth/login/password`, { user_name: "nobody", password: "anything-at-all-123" });
    expect((login.body as Problem).detail).toBe((unknown.body as Problem).detail);

    const set = await patch(`${V}/users/${ACCESS_IDS.serviceAccount}`, { password: "correct-horse-battery-81" });
    expectProblem(set, 409, "auth.service_account.no_login");
    expect(findUserByName("dns-sync")?.password).toBeNull();
  });
});

// ---------------------------------------------------------------------------------
// Grants

describe("grants", () => {
  it("creates a grant with a Location and bumps the revision", async () => {
    const before = db.revision;
    const answer = await createGrant({
      subject: MOCK_USER_IDS.sam,
      role: "viewer",
      scope: prefixRule(IPAM_IDS.prefix.lan, false),
    });
    expect(answer.status).toBe(201);
    expect(answer.body).toMatchObject({
      subject: { id: MOCK_USER_IDS.sam, name: "sam", kind: "person" },
      role: "viewer",
      scope: prefixRule(IPAM_IDS.prefix.lan, false),
      delegable: false,
      granted_by: ALEX,
    });
    expect(answer.body.parent).toBeUndefined();
    expect(answer.res.headers.get("location")).toBe(`${V}/access/grants/${answer.body.id}`);
    expect(db.revision).toBe(before + 1);
    const event = db.journal[db.journal.length - 1];
    expect(event?.topic).toBe("admin");
    expect(event?.data.objects).toContainEqual({ kind: "grant", id: answer.body.id });

    const vrf = await createGrant({ subject: MOCK_USER_IDS.sam, role: "operator", scope: { kind: "vrf", value: IPAM_IDS.vrf.default }, delegable: true });
    expect(vrf.status).toBe(201);
    expect(vrf.body.delegable).toBe(true);
  });

  it("lists by holder name then age, narrowed by ?subject=", async () => {
    await createGrant({ subject: CASEY, role: "viewer", scope: siteRule(IPAM_IDS.site.garage, false) });
    const all = await grantsOf();
    expect(all.map((g) => g.subject.name)).toEqual(["casey", "casey", "casey", "dns-sync"]);
    expect(all[2]?.scope).toEqual(siteRule(IPAM_IDS.site.garage, false));
    expect((await grantsOf(`?subject=${ACCESS_IDS.serviceAccount}`)).map((g) => g.id)).toEqual([ACCESS_IDS.serviceAccountGrant]);
    expect(await grantsOf(`?subject=${MOCK_USER_IDS.sam}`)).toEqual([]);
    expectProblem(await get(`${V}/access/grants?subject=nope`), 400, "sys.invalid_query");
  });

  it("refuses duplicates, global-only roles, scopes that cannot be granted and bad subjects", async () => {
    const dup = await createGrant({ subject: CASEY, role: "operator", scope: prefixRule(IPAM_IDS.prefix.documentation) });
    expectProblem(dup, 409, "auth.grant.duplicate");
    // The same role over the same prefix without the subtree is another scope.
    expect((await createGrant({ subject: CASEY, role: "operator", scope: prefixRule(IPAM_IDS.prefix.documentation, false) })).status).toBe(201);

    for (const role of ["admin", "auditor"]) {
      const bad = expectProblem(await createGrant({ subject: CASEY, role, scope: siteRule(IPAM_IDS.site.home) }), 422, "auth.grant.invalid_role");
      expect(bad.params.role).toBe(role);
    }
    expectProblem(
      await createGrant({ subject: CASEY, role: "viewer", scope: { kind: "tenant", value: IPAM_IDS.tenant.default } }),
      422,
      "auth.grant.invalid_scope",
    );
    expectProblem(
      await createGrant({ subject: CASEY, role: "viewer", scope: { kind: "object", value: { kind: "host", id: IPAM_IDS.tenant.default } } }),
      422,
      "auth.grant.invalid_scope",
    );
    for (const scope of [
      siteRule("0190d1c2-0000-7000-8000-0000000e9999"),
      prefixRule("0190d1c2-0000-7000-8000-0000000e9998"),
      { kind: "vrf", value: "0190d1c2-0000-7000-8000-0000000e9997" },
    ]) {
      expectProblem(await createGrant({ subject: CASEY, role: "viewer", scope }), 422, "auth.grant.invalid_scope");
    }
    expectProblem(await createGrant({ subject: CASEY, role: "viewer", scope: { kind: "zone", value: "x" } }), 400, "auth.invalid_request");
    expectProblem(await createGrant({ subject: CASEY, role: "viewer" }), 400, "auth.invalid_request");
    expectProblem(
      await createGrant({ subject: "0190d1c2-0000-7000-8000-0000000e9996", role: "viewer", scope: siteRule(IPAM_IDS.site.home) }),
      404,
      "users.not_found",
    );
    // The break-glass account holds the admin role only.
    expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.breakglass, role: "viewer", scope: siteRule(IPAM_IDS.site.home) }),
      400,
      "auth.invalid_request",
    );
  });

  it("revokes a grant with the grants issued under it, the requested one first", async () => {
    const top = await createGrant({ subject: CASEY, role: "operator", scope: siteRule(IPAM_IDS.site.home), delegable: true });
    signInAs("casey", "password");
    const child = await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: siteRule(IPAM_IDS.site.garage), delegable: true });
    expect(child.status).toBe(201);
    expect(child.body.parent).toBe(top.body.id);
    expect(child.body.granted_by).toBe(CASEY);
    signInAs("sam");
    const grandchild = await createGrant({ subject: MOCK_USER_IDS.robin, role: "viewer", scope: siteRule(IPAM_IDS.site.garage, false) });
    expect(grandchild.body.parent).toBe(child.body.id);

    signInAs("alex");
    const revoked = await del<{ revoked: string[] }>(`${V}/access/grants/${top.body.id}`);
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked[0]).toBe(top.body.id);
    expect([...revoked.body.revoked].sort()).toEqual([top.body.id, child.body.id, grandchild.body.id].sort());
    expect((await grantsOf()).map((g) => g.id)).not.toContain(grandchild.body.id);
    expect((await grantsOf()).map((g) => g.id)).toContain(ACCESS_IDS.operatorGrant);

    const again = expectProblem(await del(`${V}/access/grants/${top.body.id}`), 404, "auth.grant.not_found");
    expect(again.params.kind).toBe("grant");
  });

  it("removes the grants and tokens of a deleted account", async () => {
    expect((await del(`${V}/users/${CASEY}`)).status).toBe(204);
    expect((await grantsOf()).map((g) => g.subject.name)).toEqual(["dns-sync"]);
    expect((await del(`${V}/users/${ACCESS_IDS.serviceAccount}`)).status).toBe(204);
    expect(await grantsOf()).toEqual([]);
    expect(db.tokens.some((t) => t.info.scoped)).toBe(false);
    expect(access.tokens.size).toBe(0);
    expect(access.accounts.size).toBe(0);
  });

  it("lists the enabled people and service accounts a grant can name", async () => {
    const subjects = await get<Page<S["GrantSubject"]>>(`${V}/access/subjects`);
    expect(subjects.status).toBe(200);
    // robin is disabled in the seed and the break-glass account holds no grants.
    expect(subjects.body.items.map((s) => [s.name, s.kind])).toEqual([
      ["alex", "person"],
      ["casey", "person"],
      ["dns-sync", "service"],
      ["sam", "person"],
    ]);

    signInAs("casey", "password");
    expectProblem(await get(`${V}/access/subjects`), 403, "auth.forbidden");
    signInAs("alex");
    await createGrant({ subject: CASEY, role: "viewer", scope: siteRule(IPAM_IDS.site.home), delegable: true });
    signInAs("casey", "password");
    expect((await get<Page<S["GrantSubject"]>>(`${V}/access/subjects`)).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------
// Delegation

describe("delegation", () => {
  async function delegableViewer(): Promise<GrantView> {
    const answer = await createGrant({ subject: CASEY, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.documentation), delegable: true });
    expect(answer.status).toBe(201);
    signInAs("casey", "password");
    return answer.body;
  }

  it("lets the holder of a delegable grant hand out a role no higher inside its scope", async () => {
    const parent = await delegableViewer();
    const inside = await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) });
    expect(inside.status).toBe(201);
    expect(inside.body.parent).toBe(parent.id);
    expect(inside.body.granted_by).toBe(CASEY);
    // The cameras prefix is below the documentation prefix, not below the lab prefix.
    expect((await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.cameras) })).status).toBe(201);
    // The VRF and the site are not decided by the prefix tree: no.
    expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: { kind: "vrf", value: IPAM_IDS.vrf.default } }),
      403,
      "auth.grant.exceeds_own",
    );
  });

  it("refuses a delegation beyond the own role or scope", async () => {
    await delegableViewer();
    const operator = expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.sam, role: "operator", scope: prefixRule(IPAM_IDS.prefix.lab) }),
      403,
      "auth.grant.exceeds_own",
    );
    expect(operator.detail).toBeTruthy();
    for (const scope of [prefixRule(IPAM_IDS.prefix.lan), prefixRule(IPAM_IDS.prefix.iot), siteRule(IPAM_IDS.site.home)]) {
      expectProblem(await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope }), 403, "auth.grant.exceeds_own");
    }
    // The subtree flag: an inner rule with a subtree is not inside a rule without.
    signInAs("alex");
    await createGrant({ subject: CASEY, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lan, false), delegable: true });
    signInAs("casey", "password");
    expect((await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lan, false) })).status).toBe(201);
    expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lan, true) }),
      403,
      "auth.grant.exceeds_own",
    );
  });

  it("refuses a holder of no delegable grant, whatever the grant says", async () => {
    signInAs("casey", "password");
    expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) }),
      403,
      "auth.grant.exceeds_own",
    );
    signInAs("sam");
    expectProblem(
      await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) }),
      403,
      "auth.grant.exceeds_own",
    );
  });

  it("shows a delegate its own grants and those issued under them, and lets it revoke those", async () => {
    const parent = await delegableViewer();
    const child = await createGrant({ subject: MOCK_USER_IDS.sam, role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) });
    expect((await grantsOf()).map((g) => g.id).sort()).toEqual([ACCESS_IDS.operatorGrant, ACCESS_IDS.viewerGrant, parent.id, child.body.id].sort());
    expect((await grantsOf(`?subject=${MOCK_USER_IDS.sam}`)).map((g) => g.id)).toEqual([child.body.id]);

    // Not a grant of casey, and not under one.
    expectProblem(await del(`${V}/access/grants/${ACCESS_IDS.serviceAccountGrant}`), 404, "auth.grant.not_found");
    const revoked = await del<{ revoked: string[] }>(`${V}/access/grants/${child.body.id}`);
    expect(revoked.body.revoked).toEqual([child.body.id]);
  });
});

// ---------------------------------------------------------------------------------
// Service accounts and their tokens

describe("service accounts", () => {
  it("creates an account owned by the administrator", async () => {
    const before = db.revision;
    const answer = await post<UserInfo>(`${V}/access/service-accounts`, { name: "backup-agent", display_name: "Backup agent", roles: [] });
    expect(answer.status).toBe(201);
    expect(answer.body).toMatchObject({
      name: "backup-agent",
      display_name: "Backup agent",
      roles: [],
      kind: "service",
      owner: ALEX,
      disabled: false,
      factors: { password: false, totp: false, webauthn: 0, hardware_keys: 0, recovery_codes: 0 },
    });
    expect(answer.res.headers.get("location")).toBe(`${V}/users/${answer.body.id}`);
    expect(db.revision).toBe(before + 1);

    const defaults = await post<UserInfo>(`${V}/access/service-accounts`, { name: "metrics-agent", roles: ["viewer", "viewer"] });
    expect(defaults.body).toMatchObject({ display_name: "metrics-agent", roles: ["viewer"] });
    expect((await get<Page<UserInfo>>(`${V}/access/service-accounts`)).body.items.map((u) => u.name)).toEqual([
      "backup-agent",
      "dns-sync",
      "metrics-agent",
    ]);
    // It is a user as well.
    expect((await get<UserInfo>(`${V}/users/${answer.body.id}`)).body.kind).toBe("service");
  });

  it("refuses a taken or bad name and anybody but an administrator", async () => {
    expectProblem(await post(`${V}/access/service-accounts`, { name: "dns-sync" }), 409, "users.name_taken");
    expectProblem(await post(`${V}/access/service-accounts`, { name: "ALEX" }), 409, "users.name_taken");
    for (const name of ["", "has space", "tab\tname", "x".repeat(65)]) {
      expectProblem(await post(`${V}/access/service-accounts`, { name }), 400, "auth.invalid_request");
    }
    expectProblem(await post(`${V}/access/service-accounts`, { name: "ok", roles: ["root"] }), 400, "auth.invalid_request");
    expect((await post(`${V}/access/service-accounts`, { name: "x".repeat(64) })).status).toBe(201);

    signInAs("sam");
    expectProblem(await post(`${V}/access/service-accounts`, { name: "sams-bot" }), 403, "auth.forbidden");
    // An operator reads users, so reads the accounts, but not their tokens.
    expect((await get(`${V}/access/service-accounts`)).status).toBe(200);
    expectProblem(await get(`${V}/access/service-accounts/${ACCESS_IDS.serviceAccount}/tokens`), 403, "auth.forbidden");
    signInAs("casey", "password");
    expectProblem(await get(`${V}/access/service-accounts`), 403, "auth.forbidden");
  });

  it("creates scoped tokens only, shows the secret once and revokes them", async () => {
    const path = `${V}/access/service-accounts/${ACCESS_IDS.serviceAccount}/tokens`;
    const created = await post<CreatedToken>(path, {
      name: "ipam-writer",
      expires_in_days: 30,
      grants: [{ role: "viewer", scope: siteRule(IPAM_IDS.site.garage) }],
    });
    expect(created.status).toBe(201);
    expect(created.body.token).toMatch(/^tnk_[A-Za-z0-9_-]{20,}$/);
    expect(created.body.info).toMatchObject({
      name: "ipam-writer",
      scoped: true,
      grants: [{ role: "viewer", scope: siteRule(IPAM_IDS.site.garage) }],
      scopes: [],
    });
    expect(created.body.token.startsWith(created.body.info.prefix)).toBe(true);
    expect(created.body.info.prefix.length).toBeLessThan(created.body.token.length);

    const list = await get<Page<TokenInfo>>(path);
    expect(list.body.items.map((t) => t.name)).toEqual(["ipam-readonly", "ipam-writer"]);
    expect(JSON.stringify(list.body)).not.toContain(created.body.token);

    const scopes = await post<CreatedToken>(path, { name: "prometheus", expires_in_days: 7, scopes: ["metrics"] });
    expect(scopes.status).toBe(201);
    expect(scopes.body.info).toMatchObject({ scoped: true, scopes: ["metrics"] });
    expect(scopes.body.info.grants).toEqual([]);
    // The token is the account's: it is not among alex's tokens.
    expect((await get<Page<TokenInfo>>(`${V}/auth/tokens`)).body.items.map((t) => t.name)).not.toContain("prometheus");

    expect((await del(`${path}/${created.body.info.id}`)).status).toBe(204);
    expectProblem(await del(`${path}/${created.body.info.id}`), 404, "auth.token.not_found");
    // A token of another account is not found under this one.
    expectProblem(await del(`${path}/${MOCK_USER_IDS.alex}`), 404, "auth.token.not_found");
    expect((await get<Page<TokenInfo>>(path)).body.items.map((t) => t.name)).toEqual(["ipam-readonly", "prometheus"]);
    expect(access.tokens.has(created.body.info.id)).toBe(false);
  });

  it("refuses a body without grants and scopes, and what the account cannot give", async () => {
    const path = `${V}/access/service-accounts/${ACCESS_IDS.serviceAccount}/tokens`;
    expectProblem(await post(path, { name: "personal" }), 400, "auth.invalid_request");
    expectProblem(await post(path, { name: "empty", grants: [], scopes: [] }), 400, "auth.invalid_request");
    expectProblem(await post(path, { name: "" , scopes: ["metrics"] }), 400, "auth.invalid_request");
    expectProblem(await post(path, { name: "bad", scopes: ["root"] }), 400, "auth.invalid_request");

    // dns-sync holds no global role: a global grant is beyond it, and a scope outside its site too.
    expectProblem(await post(path, { name: "g", grants: [{ role: "viewer" }] }), 403, "auth.grant.exceeds_own");
    expectProblem(
      await post(path, { name: "g", grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lan) }] }),
      403,
      "auth.grant.exceeds_own",
    );
    expectProblem(
      await post(path, { name: "g", grants: [{ role: "operator", scope: siteRule(IPAM_IDS.site.home) }] }),
      403,
      "auth.grant.exceeds_own",
    );
    expectProblem(
      await post(path, { name: "g", grants: [{ role: "admin", scope: siteRule(IPAM_IDS.site.home) }] }),
      422,
      "auth.grant.invalid_role",
    );
    expectProblem(
      await post(path, { name: "g", grants: [{ role: "viewer", scope: siteRule("0190d1c2-0000-7000-8000-0000000e9999") }] }),
      422,
      "auth.grant.invalid_scope",
    );
    // A service account may ask for a special scope.
    expect((await post(path, { name: "audit", scopes: ["audit:read"] })).status).toBe(201);

    // The lifetime holds to the profile maximum (TGL-05, 90 days in Standard).
    const long = expectProblem(
      await post(path, { name: "long", expires_in_days: 91, scopes: ["metrics"] }),
      422,
      "auth.token.lifetime_exceeded",
    );
    expect(long.params).toEqual({ max_days: "90" });
    const dflt = await post<CreatedToken>(path, { name: "default", scopes: ["metrics"] });
    const days = (Date.parse(dflt.body.info.expires_at as string) - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(90);
    expectProblem(await post(path, { name: "zero", expires_in_days: 0, scopes: ["metrics"] }), 400, "auth.invalid_request");

    expectProblem(await post(`${V}/access/service-accounts/${MOCK_USER_IDS.sam}/tokens`, { name: "n", scopes: ["metrics"] }), 404, "auth.service_account.not_found");
    expectProblem(await get(`${V}/access/service-accounts/${MOCK_USER_IDS.sam}/tokens`), 404, "auth.service_account.not_found");
    expectProblem(await del(`${V}/access/service-accounts/${MOCK_USER_IDS.sam}/tokens/${ACCESS_IDS.serviceToken}`), 404, "auth.service_account.not_found");
    expectProblem(
      await post(`${V}/access/service-accounts/0190d1c2-0000-7000-8000-0000000e9990/tokens`, { name: "n", scopes: ["metrics"] }),
      404,
      "auth.service_account.not_found",
    );

    // A role of the account's own covers a global grant.
    const bot = await post<UserInfo>(`${V}/access/service-accounts`, { name: "ops-bot", roles: ["operator"] });
    const botPath = `${V}/access/service-accounts/${bot.body.id}/tokens`;
    expect((await post(botPath, { name: "g", grants: [{ role: "viewer" }] })).status).toBe(201);
    expectProblem(await post(botPath, { name: "g", grants: [{ role: "admin" }] }), 403, "auth.grant.exceeds_own");
  });

  it("needs a session that meets the strength of the administrator", async () => {
    signInAs("alex", "password");
    db.settings = { ...db.settings, passkey_for_admins: true };
    const answer = await post(`${V}/access/service-accounts/${ACCESS_IDS.serviceAccount}/tokens`, { name: "n", scopes: ["metrics"] });
    const problem = expectProblem(answer, 403, "auth.step_up_required");
    expect(problem.params.required).toBe("passkey");
  });
});

// ---------------------------------------------------------------------------------
// Role policies

describe("role policies", () => {
  const policy = async (role: string): Promise<RolePolicyView> => {
    const list = await get<Page<RolePolicyView>>(`${V}/access/role-policies`);
    return list.body.items.find((p) => p.role === role) as RolePolicyView;
  };

  it("lists the four roles with the profile's requirement and no stored policy", async () => {
    const list = await get<Page<RolePolicyView>>(`${V}/access/role-policies`);
    expect(list.status).toBe(200);
    expect(list.body.items.map((p) => p.role)).toEqual(["admin", "operator", "viewer", "auditor"]);
    for (const item of list.body.items) {
      expect(item.mfa).toBe(item.profile_default);
      expect(item.stored).toBeUndefined();
    }
    // Standard: multi-factor for administrators only.
    expect(list.body.items.map((p) => p.profile_default)).toEqual(["totp_or_stronger", "optional", "optional", "optional"]);
  });

  it("stores a policy, keeps the stricter of it and the profile, and clears it", async () => {
    const before = db.revision;
    const set = await put<RolePolicyView>(`${V}/access/role-policies/viewer`, { mfa: "totp_or_stronger" });
    expect(set.status).toBe(200);
    expect(set.body).toEqual({ role: "viewer", mfa: "totp_or_stronger", profile_default: "optional", stored: "totp_or_stronger" });
    expect(db.revision).toBe(before + 1);
    expect(db.journal[db.journal.length - 1]?.data.tables).toContain("auth.role_policies");
    // The same value again changes nothing.
    await put(`${V}/access/role-policies/viewer`, { mfa: "totp_or_stronger" });
    expect(db.revision).toBe(before + 1);

    // A policy weaker than the profile has no effect beyond it.
    const weak = await put<RolePolicyView>(`${V}/access/role-policies/admin`, { mfa: "optional" });
    expect(weak.body).toEqual({ role: "admin", mfa: "totp_or_stronger", profile_default: "totp_or_stronger", stored: "optional" });
    expect(db.revision).toBe(before + 2);

    const cleared = await del<RolePolicyView>(`${V}/access/role-policies/viewer`);
    expect(cleared.status).toBe(200);
    expect(cleared.body).toEqual({ role: "viewer", mfa: "optional", profile_default: "optional" });
    expect((await policy("viewer")).stored).toBeUndefined();
    await del(`${V}/access/role-policies/viewer`);
    expect(db.revision).toBe(before + 3);
  });

  it("refuses a bad role or value and anybody but an administrator", async () => {
    expectProblem(await put(`${V}/access/role-policies/root`, { mfa: "passkey" }), 400, "auth.invalid_request");
    expectProblem(await put(`${V}/access/role-policies/viewer`, { mfa: "always" }), 400, "auth.invalid_request");
    expectProblem(await put(`${V}/access/role-policies/viewer`, {}), 400, "auth.invalid_request");
    expectProblem(await del(`${V}/access/role-policies/root`), 400, "auth.invalid_request");
    signInAs("sam");
    expect((await get(`${V}/access/role-policies`)).status).toBe(200);
    expectProblem(await put(`${V}/access/role-policies/viewer`, { mfa: "passkey" }), 403, "auth.forbidden");
    expectProblem(await del(`${V}/access/role-policies/viewer`), 403, "auth.forbidden");
    signInAs("casey", "password");
    expectProblem(await get(`${V}/access/role-policies`), 403, "auth.forbidden");
  });

  it("shows up in required_strength for global roles and for roles held through grants", async () => {
    // casey holds operator and viewer through grants only.
    expect((await loginAsCasey()).required_strength).toBe("password");

    signInAs("alex");
    await put(`${V}/access/role-policies/viewer`, { mfa: "totp_or_stronger" });
    const totp = await loginAsCasey();
    expect(totp.required_strength).toBe("password_totp");
    expect(totp.flags.mfa_enrolment_required).toBe(true);
    // A global role that has no policy is not affected.
    signInAs("sam");
    expect((await get<SessionInfo>(`${V}/auth/session`)).body.required_strength).toBe("password");

    signInAs("alex");
    await put(`${V}/access/role-policies/operator`, { mfa: "passkey" });
    expect((await loginAsCasey()).required_strength).toBe("passkey");
    signInAs("sam");
    expect((await get<SessionInfo>(`${V}/auth/session`)).body.required_strength).toBe("passkey");

    signInAs("alex");
    await del(`${V}/access/role-policies/operator`);
    await del(`${V}/access/role-policies/viewer`);
    const back = await loginAsCasey();
    expect(back.required_strength).toBe("password");
    expect(back.flags.mfa_enrolment_required).toBe(false);
  });

  it("takes a grant to make a policy apply to somebody who holds no such role", async () => {
    await put(`${V}/access/role-policies/auditor`, { mfa: "passkey" });
    expect((await loginAsCasey()).required_strength).toBe("password");
    signInAs("alex");
    await createGrant({ subject: CASEY, role: "viewer", scope: siteRule(IPAM_IDS.site.lab) });
    // viewer has no policy, auditor is global-only: still the profile.
    expect((await loginAsCasey()).required_strength).toBe("password");
  });
});

// ---------------------------------------------------------------------------------
// Scoped personal tokens

describe("scoped personal tokens", () => {
  it("creates a scoped token for casey inside its grants and lists it", async () => {
    await loginAsCasey();
    const created = await post<CreatedToken>(`${V}/auth/tokens`, {
      name: "lab-reader",
      expires_in_days: 14,
      grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) }],
    });
    expect(created.status).toBe(201);
    expect(created.body.token).toMatch(/^tnk_/);
    expect(created.body.info).toMatchObject({
      name: "lab-reader",
      scoped: true,
      grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) }],
      scopes: [],
    });
    const list = await get<Page<TokenInfo>>(`${V}/auth/tokens`);
    expect(list.body.items).toHaveLength(1);
    expect(list.body.items[0]).toMatchObject({ id: created.body.info.id, scoped: true });
    expect(JSON.stringify(list.body)).not.toContain(created.body.token);

    // The operator grant covers the viewer role; the viewer grant of the other prefix does not reach this one.
    expect(
      (await post(`${V}/auth/tokens`, { name: "op", grants: [{ role: "operator", scope: prefixRule(IPAM_IDS.prefix.dmz, false) }] })).status,
    ).toBe(201);
    expect(
      (await post(`${V}/auth/tokens`, { name: "iot", grants: [{ role: "operator", scope: prefixRule(IPAM_IDS.prefix.iot) }] })).status,
    ).toBe(403);

    expect((await del(`${V}/auth/tokens/${created.body.info.id}`)).status).toBe(204);
    expect(access.tokens.has(created.body.info.id)).toBe(false);
  });

  it("refuses what goes beyond the grants of the owner", async () => {
    await loginAsCasey();
    const refuse = async (body: Record<string, unknown>, status: number, code: string) =>
      expectProblem(await post(`${V}/auth/tokens`, { name: "t", ...body }), status, code);
    await refuse({ grants: [{ role: "viewer" }] }, 403, "auth.grant.exceeds_own");
    await refuse({ grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lan) }] }, 403, "auth.grant.exceeds_own");
    await refuse({ grants: [{ role: "viewer", scope: siteRule(IPAM_IDS.site.home) }] }, 403, "auth.grant.exceeds_own");
    await refuse({ grants: [{ role: "viewer", scope: { kind: "vrf", value: IPAM_IDS.vrf.default } }] }, 403, "auth.grant.exceeds_own");
    // The IoT grant is a viewer grant: it does not cover operator.
    await refuse({ grants: [{ role: "operator", scope: prefixRule(IPAM_IDS.prefix.iot) }] }, 403, "auth.grant.exceeds_own");
    await refuse({ scopes: ["metrics"] }, 403, "auth.grant.exceeds_own");
    await refuse({ scopes: ["audit:read"] }, 403, "auth.grant.exceeds_own");
    await refuse({ grants: [{ role: "admin", scope: prefixRule(IPAM_IDS.prefix.lab) }] }, 422, "auth.grant.invalid_role");
    await refuse({ grants: [{ role: "viewer", scope: prefixRule("0190d1c2-0000-7000-8000-0000000e9998") }] }, 422, "auth.grant.invalid_scope");
    await refuse({ grants: [] }, 400, "auth.invalid_request");
    await refuse({ grants: [{ role: "boss" }] }, 400, "auth.invalid_request");
    await refuse({ expires_in_days: 91, grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.lab) }] }, 422, "auth.token.lifetime_exceeded");
    expect((await get<Page<TokenInfo>>(`${V}/auth/tokens`)).body.items).toEqual([]);
  });

  it("lets a global role cover global grants and special scopes, and keeps the plain call personal", async () => {
    const ok = await post<CreatedToken>(`${V}/auth/tokens`, {
      name: "all-viewer",
      grants: [{ role: "viewer" }, { role: "operator", scope: siteRule(IPAM_IDS.site.home) }],
      scopes: ["metrics", "audit:read", "metrics"],
    });
    expect(ok.status).toBe(201);
    expect(ok.body.info).toMatchObject({ scoped: true, scopes: ["audit:read", "metrics"] });
    expect(ok.body.info.grants).toHaveLength(2);

    const plain = await post<CreatedToken>(`${V}/auth/tokens`, { name: "personal" });
    expect(plain.status).toBe(201);
    expect(plain.body.info.scoped).toBeUndefined();
    expect(plain.body.info.grants).toBeUndefined();

    // sam is an operator: viewer is covered, admin is not, and a special scope is fine.
    signInAs("sam");
    expect((await post(`${V}/auth/tokens`, { name: "s", grants: [{ role: "viewer" }], scopes: ["metrics"] })).status).toBe(201);
    expectProblem(await post(`${V}/auth/tokens`, { name: "s", grants: [{ role: "admin" }] }), 403, "auth.grant.exceeds_own");
  });

  it("needs a session at the strength the policies of the roles ask for", async () => {
    await put(`${V}/access/role-policies/viewer`, { mfa: "totp_or_stronger" });
    await loginAsCasey();
    const refused = expectProblem(
      await post(`${V}/auth/tokens`, { name: "t", grants: [{ role: "viewer", scope: prefixRule(IPAM_IDS.prefix.iot) }] }),
      403,
      "auth.step_up_required",
    );
    expect(refused.params.required).toBe("password_totp");
  });
});

// ---------------------------------------------------------------------------------
// Sign-in state

describe("signed out", () => {
  it("answers 401 without a session", async () => {
    resetMockDb("signed-out");
    seedAccess();
    expectProblem(await get(`${V}/access/grants`), 401, "auth.unauthenticated");
    expectProblem(await post(`${V}/access/grants`, {}), 401, "auth.unauthenticated");
    expectProblem(await get(`${V}/access/role-policies`), 401, "auth.unauthenticated");
    expectProblem(await get(`${V}/access/service-accounts`), 401, "auth.unauthenticated");
    expectProblem(await get(`${V}/access/subjects`), 401, "auth.unauthenticated");
  });

  it("lets casey sign in with the documented password", async () => {
    resetMockDb("signed-out");
    seedAccess();
    const session = await loginAsCasey();
    expect(session.user.name).toBe("casey");
    expect(MOCK_PASSWORDS).not.toHaveProperty("casey");
  });
});
