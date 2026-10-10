// The operator secrets mock through `fetch`, against the msw server that
// src/app/testing/setup.ts starts: the secrets, their references, the reveal under each
// policy, the credentials of a host and the remote hand-off. Values are test values.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { rdpFile } from "../../hosts/handoff";
import type { components } from "../generated/schema";
import type { AuditRecord, LoginResponse, Page } from "../types";
import { audit } from "./audit-store";
import { db, findUserByName, resetMockDb } from "./db";
import { MOCK_PASSWORDS, MOCK_USER_IDS } from "./fixtures";
import { HOST_IDS, INTERFACE_IDS } from "./ipam/api";
import {
  SEED_HOST_ID,
  SEED_SECRET_IDS,
  SEED_SECRET_VALUES,
  ageCurrentSession,
  bindSecret,
  mockSecrets,
  revealsOf,
  secretList,
  secretValue,
  seedSecret,
} from "./secrets-store";

type S = components["schemas"];
type SecretView = S["OperatorSecretView"];

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
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: { field: string; code: string }[];
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

/** Signs in as sam (an operator) or robin (a viewer; the seed has the account disabled). */
async function loginAs(name: "sam" | "robin"): Promise<void> {
  const user = findUserByName(name);
  if (user) user.disabled = false;
  const answer = await post<LoginResponse>("/api/v1/auth/login/password", {
    user_name: name,
    password: MOCK_PASSWORDS[name],
  });
  expect(answer.status).toBe(200);
  expect(answer.body.status).toBe("authenticated");
}

const V = "/api/v1";
const secretPath = (id: string) => `${V}/secrets/${id}`;
const revealPath = (id: string) => `${V}/secrets/${id}/reveal`;
const credentialsPath = (host: string) => `${V}/hosts/${host}/credentials`;
const remotePath = (host: string, query: string) => `${V}/hosts/${host}/remote?${query}`;
const etagOf = (revision: number | undefined) => `"${revision}"`;

const NAS = SEED_SECRET_IDS.nasAdmin;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const NAS_HOST = HOST_IDS.nas as string;
const UNKNOWN_ID = "0190d1c2-0000-7000-8000-0000e8ffffff";
const ALEX_ID = MOCK_USER_IDS.alex;

async function list(query = ""): Promise<SecretView[]> {
  const answer = await get<Page<SecretView>>(`${V}/secrets${query}`);
  expect(answer.status).toBe(200);
  return answer.body.items;
}

async function names(query: string): Promise<string[]> {
  return (await list(query)).map((s) => s.name);
}

function setPolicy(step_up: S["RevealStepUp"], bound_host_only = false): void {
  db.settings.secret_reveal = { step_up, bound_host_only };
}

/** The events of the topic `secrets` the journal holds, oldest first. */
function secretEvents() {
  return db.journal.filter((e) => e.topic === "secrets");
}

function auditOf(action: string): AuditRecord[] {
  return audit.records.filter((r) => r.draft.action === action);
}

beforeEach(() => {
  resetMockDb("signed-in");
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------------
// The seed and the helpers

describe("the seed", () => {
  it("has nas admin bound to the host nas and an unbound unifi api", async () => {
    const page = await get<Page<SecretView>>(`${V}/secrets`);
    expect(page.status).toBe(200);
    expect(page.body.revision).toBe(db.revision);
    expect(page.body.next_cursor ?? null).toBeNull();
    expect(page.body.items.map((s) => s.name)).toEqual(["nas admin", "unifi api"]);
    expect(page.body.items[0]).toMatchObject({
      id: NAS,
      kind: "password",
      username: "admin",
      tags: ["ssh"],
      origin: "manual",
      hosts: [{ host: NAS_HOST, role: "admin" }],
    });
    expect(page.body.items[1]).toMatchObject({ id: UNIFI, kind: "api_key", tags: ["api_key", "unifi"], hosts: [] });
    expect(page.body.items[1]).not.toHaveProperty("username");
    expect(page.body.items[1]).not.toHaveProperty("last_revealed");
    expect(SEED_HOST_ID).toBe(NAS_HOST);
    expect(secretValue(NAS)).toBe(SEED_SECRET_VALUES.nasAdmin);
    expect(secretValue(UNIFI)).toBe(SEED_SECRET_VALUES.unifiApi);
  });

  it("never shows a value", async () => {
    const text = JSON.stringify((await get(`${V}/secrets`)).body) + JSON.stringify((await get(secretPath(NAS))).body);
    expect(text).not.toContain(SEED_SECRET_VALUES.nasAdmin);
    expect(text).not.toContain(SEED_SECRET_VALUES.unifiApi);
    expect(text).not.toContain('"value"');
  });

  it("starts over after a reset, switches included", async () => {
    mockSecrets.revealLimit = 1;
    mockSecrets.pinOnlyAccounts = ["ola"];
    const extra = seedSecret({ name: "extra" });
    bindSecret(NAS_HOST, extra.id, "web");
    resetMockDb("signed-in");
    expect(mockSecrets).toEqual({ pinOnlyAccounts: [], revealLimit: 10 });
    expect((await list()).map((s) => s.name)).toEqual(["nas admin", "unifi api"]);
    const credentials = await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST));
    expect(credentials.body.version).toBe(1);
    expect(credentials.body.items).toHaveLength(1);
  });

  it("has no secrets in the first-run setup scenarios", () => {
    resetMockDb("setup");
    expect(secretList()).toEqual([]);
    resetMockDb("signed-in");
    expect(secretList()).toHaveLength(2);
  });

  it("leaves the PIN coupling flag of the vault alone", () => {
    expect(db.vaultHasOperatorSecrets).toBe(false);
  });
});

describe("the test helpers", () => {
  it("seeds a secret without events or audit records", async () => {
    const revision = db.revision;
    const seq = audit.records.length;
    const view = seedSecret({ name: "router", value: "example-router-pass", tags: ["Lab", "lab", "net"], username: "root" });
    expect(view).toMatchObject({ name: "router", kind: "password", tags: ["lab", "net"], username: "root", hosts: [] });
    expect(secretValue(view.id)).toBe("example-router-pass");
    expect(db.revision).toBe(revision);
    expect(audit.records).toHaveLength(seq);
    expect((await get<SecretView>(secretPath(view.id))).body.name).toBe("router");
  });

  it("binds a secret and raises the version of the host", async () => {
    const extra = seedSecret({ name: "extra" });
    bindSecret(NAS_HOST, extra.id, "web");
    const answer = await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST));
    expect(answer.body.version).toBe(2);
    expect(answer.body.items.map((i) => [i.role, i.secret.name])).toEqual([
      ["admin", "nas admin"],
      ["web", "extra"],
    ]);
    expect(() => bindSecret(NAS_HOST, UNKNOWN_ID, "web")).toThrow();
    expect(() => secretValue(UNKNOWN_ID)).toThrow();
  });

  it("ages the current session, and fails without one", () => {
    const session = db.sessions.find((s) => s.id === db.currentSessionId);
    const before = session?.created_at ?? 0;
    ageCurrentSession(120);
    expect(before - (session?.created_at ?? 0)).toBe(120_000);
    resetMockDb("signed-out");
    expect(() => ageCurrentSession(1)).toThrow();
  });
});

// ---------------------------------------------------------------------------------
// Who may see and change what

describe("sessions and roles", () => {
  it("needs a session", async () => {
    resetMockDb("signed-out");
    expectProblem(await get(`${V}/secrets`), 401, "auth.unauthenticated");
    expectProblem(await post(`${V}/secrets`, {}), 401, "auth.unauthenticated");
    expectProblem(await get(secretPath(NAS)), 401, "auth.unauthenticated");
    expectProblem(await patch(secretPath(NAS), {}), 401, "auth.unauthenticated");
    expectProblem(await del(secretPath(NAS)), 401, "auth.unauthenticated");
    expectProblem(await get(`${secretPath(NAS)}/references`), 401, "auth.unauthenticated");
    expectProblem(await post(revealPath(NAS)), 401, "auth.unauthenticated");
    expectProblem(await get(credentialsPath(NAS_HOST)), 401, "auth.unauthenticated");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [] }), 401, "auth.unauthenticated");
    expectProblem(await get(remotePath(NAS_HOST, "protocol=ssh")), 401, "auth.unauthenticated");
  });

  it("gives a viewer an empty list and nothing else", async () => {
    await loginAs("robin");
    const page = await get<Page<SecretView>>(`${V}/secrets`);
    expect(page.status).toBe(200);
    expect(page.body.items).toEqual([]);
    expectProblem(await get(secretPath(NAS)), 403, "auth.forbidden");
    expectProblem(await get(`${secretPath(NAS)}/references`), 403, "auth.forbidden");
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "other", value: "y" }), 403, "auth.forbidden");
    expectProblem(await patch(secretPath(NAS), { name: "x" }), 403, "auth.forbidden");
    expectProblem(await del(secretPath(UNIFI)), 403, "auth.forbidden");
    expectProblem(await post(revealPath(NAS)), 403, "auth.forbidden");
    expectProblem(await get(credentialsPath(NAS_HOST)), 403, "auth.forbidden");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [] }), 403, "auth.forbidden");
    // The paging parameters of a viewer's list are still checked.
    expectProblem(await get(`${V}/secrets?limit=0`), 400, "sys.invalid_query");
  });

  it("lets an operator read and reveal but not change", async () => {
    await loginAs("sam");
    expect(await names("")).toEqual(["nas admin", "unifi api"]);
    expect((await get(secretPath(NAS))).status).toBe(200);
    expect((await get(`${secretPath(NAS)}/references`)).status).toBe(200);
    expect((await get(credentialsPath(NAS_HOST))).status).toBe(200);
    expect((await post(revealPath(NAS))).status).toBe(200);
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "other", value: "y" }), 403, "auth.forbidden");
    expectProblem(await patch(secretPath(NAS), { name: "x" }), 403, "auth.forbidden");
    expectProblem(await del(secretPath(UNIFI)), 403, "auth.forbidden");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [] }), 403, "auth.forbidden");
  });
});

// ---------------------------------------------------------------------------------
// The list

describe("the list", () => {
  it("sorts by name ignoring case", async () => {
    seedSecret({ name: "Zulu" });
    seedSecret({ name: "alpha" });
    seedSecret({ name: "Bravo" });
    expect(await names("")).toEqual(["alpha", "Bravo", "nas admin", "unifi api", "Zulu"]);
  });

  it("filters by text over the name, the user name and the tags", async () => {
    seedSecret({ name: "backup target", username: "Svc-Backup", tags: ["restic"] });
    expect(await names("?q=NAS")).toEqual(["nas admin"]);
    expect(await names("?q=svc-back")).toEqual(["backup target"]);
    expect(await names("?q=ADMIN")).toEqual(["nas admin"]);
    expect(await names("?q=restic")).toEqual(["backup target"]);
    expect(await names("?q=nothing")).toEqual([]);
  });

  it("filters by kind, tag and host", async () => {
    expect(await names("?kind=api_key")).toEqual(["unifi api"]);
    expect(await names("?kind=ssh_key")).toEqual([]);
    expect(await names("?tag=unifi")).toEqual(["unifi api"]);
    expect(await names("?tag=UNIFI")).toEqual(["unifi api"]);
    expect(await names("?tag=uni")).toEqual([]);
    expect(await names(`?host=${NAS_HOST}`)).toEqual(["nas admin"]);
    expect(await names(`?host=${UNKNOWN_ID}`)).toEqual([]);
    expect(await names(`?kind=password&q=nas&host=${NAS_HOST}`)).toEqual(["nas admin"]);
  });

  it("pages with a cursor", async () => {
    const first = await get<Page<SecretView>>(`${V}/secrets?limit=1`);
    expect(first.body.items.map((s) => s.name)).toEqual(["nas admin"]);
    expect(first.body.next_cursor).toBeTruthy();
    const second = await get<Page<SecretView>>(
      `${V}/secrets?limit=1&cursor=${encodeURIComponent(first.body.next_cursor ?? "")}`,
    );
    expect(second.body.items.map((s) => s.name)).toEqual(["unifi api"]);
    expect(second.body.next_cursor ?? null).toBeNull();
  });

  it("refuses a bad query", async () => {
    expectProblem(await get(`${V}/secrets?kind=nothing`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/secrets?host=nas`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/secrets?colour=blue`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/secrets?limit=0`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/secrets?cursor=%25`), 400, "sys.invalid_cursor");
  });
});

// ---------------------------------------------------------------------------------
// Create

describe("create", () => {
  it("stores the secret and answers with its metadata", async () => {
    const answer = await post<SecretView>(`${V}/secrets`, {
      name: "  Router admin ",
      kind: "password",
      tags: ["Router", "lab", "router"],
      username: " root ",
      notes: "Rack 1\nSecond line",
      value: "example-router-pass",
    });
    expect(answer.status).toBe(201);
    const view = answer.body;
    expect(view).toMatchObject({
      name: "Router admin",
      kind: "password",
      tags: ["lab", "router"],
      username: "root",
      notes: "Rack 1\nSecond line",
      origin: "manual",
      hosts: [],
    });
    expect(view.created_at).toBe(view.updated_at);
    expect(view.created_at).toBe(view.value_updated_at);
    expect(answer.res.headers.get("etag")).toBe(etagOf(view.revision ?? undefined));
    expect(JSON.stringify(view)).not.toContain("example-router-pass");
    expect(secretValue(view.id)).toBe("example-router-pass");
    expect(await names("")).toContain("Router admin");
    expect(db.vaultHasOperatorSecrets).toBe(true);
  });

  it("records an event and an audit record without the value", async () => {
    const answer = await post<SecretView>(`${V}/secrets`, { name: "router", kind: "token", value: "example-token-value" });
    const id = answer.body.id;
    const event = secretEvents().find((e) => e.id === answer.body.revision);
    expect(event?.data.objects).toEqual([{ kind: "secret", id }]);
    const record = auditOf("vault.secret.create").at(-1);
    expect(record?.draft.objects).toEqual([{ kind: "secret", id }]);
    expect(record?.draft.details?.context).toEqual({ name: "router", kind: "token" });
    expect(record?.draft.outcome).toEqual({ kind: "success" });
    expect(JSON.stringify(audit.records)).not.toContain("example-token-value");
  });

  it("checks the values and names the field", async () => {
    const base = { name: "router", kind: "password", value: "example-value" };
    const cases: [string, Record<string, unknown>][] = [
      ["name", { ...base, name: "" }],
      ["name", { ...base, name: "   " }],
      ["name", { ...base, name: "n".repeat(129) }],
      ["name", { ...base, name: "bell\u0007" }],
      ["tags", { ...base, tags: ["bad tag"] }],
      ["tags", { ...base, tags: ["a/b"] }],
      ["tags", { ...base, tags: [""] }],
      ["tags", { ...base, tags: ["t".repeat(65)] }],
      ["tags", { ...base, tags: Array.from({ length: 17 }, (_, i) => `tag${i}`) }],
      ["username", { ...base, username: "u".repeat(257) }],
      ["notes", { ...base, notes: "n".repeat(2001) }],
      ["notes", { ...base, notes: "bell\u0007" }],
      ["value", { ...base, value: "" }],
    ];
    for (const [field, body] of cases) {
      const problem = expectProblem(await post(`${V}/secrets`, body), 422, "vault.secret.invalid");
      expect(problem.params.field).toBe(field);
      expect(problem.errors?.[0]).toMatchObject({ field, code: "vault.secret.invalid" });
    }
    // A value above 64 KiB is too large, as the vault answers it.
    expectProblem(await post(`${V}/secrets`, { ...base, value: "v".repeat(64 * 1024 + 1) }), 413, "vault.secret.too_large");
    expect(await names("")).toEqual(["nas admin", "unifi api"]);
  });

  it("accepts the limits themselves", async () => {
    const answer = await post<SecretView>(`${V}/secrets`, {
      name: "n".repeat(128),
      kind: "other",
      tags: Array.from({ length: 16 }, (_, i) => `tag${i}`),
      value: "v".repeat(64 * 1024),
    });
    expect(answer.status).toBe(201);
    expect(answer.body.tags).toHaveLength(16);
  });

  it("refuses a malformed body", async () => {
    expectProblem(await post(`${V}/secrets`, { kind: "other", value: "x" }), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "colour", value: "x" }), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "other" }), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "other", value: "x", extra: 1 }), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/secrets`, { name: "x", kind: "other", value: "x", tags: "lab" }), 400, "sys.invalid_request");
    const res = await fetch(`${V}/secrets`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    expect(res.status).toBe(400);
  });

  it("is refused while an account that may reveal signs in with a PIN alone", async () => {
    mockSecrets.pinOnlyAccounts = ["ola", "kim"];
    const problem = expectProblem(
      await post(`${V}/secrets`, { name: "router", kind: "other", value: "example-value" }),
      409,
      "vault.pin_coupling",
    );
    expect(problem.params.accounts).toBe("ola,kim");
    expect(await names("")).toEqual(["nas admin", "unifi api"]);
    mockSecrets.pinOnlyAccounts = [];
    expect((await post(`${V}/secrets`, { name: "router", kind: "other", value: "example-value" })).status).toBe(201);
  });

  it("is refused to a session of PIN strength", async () => {
    const session = db.sessions.find((s) => s.id === db.currentSessionId);
    if (session) session.strength = "pin";
    const problem = expectProblem(
      await post(`${V}/secrets`, { name: "router", kind: "other", value: "example-value" }),
      403,
      "auth.step_up_required",
    );
    expect(problem.params.required).toBe("password");
  });
});

// ---------------------------------------------------------------------------------
// Read and change

describe("get and patch", () => {
  it("reads one secret with its ETag", async () => {
    const answer = await get<SecretView>(secretPath(NAS));
    expect(answer.status).toBe(200);
    expect(answer.body.name).toBe("nas admin");
    expect(answer.res.headers.get("etag")).toBe(etagOf(answer.body.revision ?? undefined));
    expectProblem(await get(secretPath(UNKNOWN_ID)), 404, "vault.secret.not_found");
    expectProblem(await get(secretPath("nothing")), 400, "sys.invalid_request");
  });

  it("changes the metadata and moves the revision", async () => {
    const before = (await get<SecretView>(secretPath(UNIFI))).body;
    const answer = await patch<SecretView>(
      secretPath(UNIFI),
      { name: "UniFi API key", kind: "token", tags: ["Prod", "unifi"], username: "api", notes: "Rotated yearly" },
      { headers: { "If-Match": etagOf(before.revision ?? undefined) } },
    );
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({
      name: "UniFi API key",
      kind: "token",
      tags: ["prod", "unifi"],
      username: "api",
      notes: "Rotated yearly",
      value_updated_at: before.value_updated_at,
    });
    expect(answer.body.revision).toBeGreaterThan(before.revision ?? 0);
    expect(answer.res.headers.get("etag")).toBe(etagOf(answer.body.revision ?? undefined));
    expect(Date.parse(answer.body.updated_at)).toBeGreaterThan(Date.parse(before.updated_at));
    expect(secretValue(UNIFI)).toBe(SEED_SECRET_VALUES.unifiApi);
    expect(secretEvents().some((e) => e.id === answer.body.revision)).toBe(true);
    const record = auditOf("vault.secret.update").at(-1);
    expect(record?.draft.details?.changes?.map((c) => c.field)).toEqual(["name", "kind", "tags", "username", "notes"]);
    // The audit record says that the notes changed, not what they say.
    expect(JSON.stringify(record)).not.toContain("Rotated yearly");
  });

  it("refuses a stale If-Match and accepts the current one and *", async () => {
    const before = (await get<SecretView>(secretPath(UNIFI))).body;
    const stale = etagOf(before.revision ?? undefined);
    expect((await patch(secretPath(UNIFI), { name: "first" }, { headers: { "If-Match": stale } })).status).toBe(200);
    const problem = expectProblem(
      await patch(secretPath(UNIFI), { name: "second" }, { headers: { "If-Match": stale } }),
      409,
      "vault.secret.conflict",
    );
    expect(problem.params.expected).toBe(String(before.revision));
    expect((await get<SecretView>(secretPath(UNIFI))).body.name).toBe("first");
    expect((await patch(secretPath(UNIFI), { name: "third" }, { headers: { "If-Match": "*" } })).status).toBe(200);
    expect((await patch(secretPath(UNIFI), { name: "fourth" })).status).toBe(200);
    expectProblem(await patch(secretPath(UNIFI), { name: "x" }, { headers: { "If-Match": "abc" } }), 400, "sys.invalid_value");
  });

  it("clears the user name and the notes with null", async () => {
    await patch(secretPath(NAS), { notes: "Rack 2" });
    const cleared = await patch<SecretView>(secretPath(NAS), { username: null, notes: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body).not.toHaveProperty("username");
    expect(cleared.body).not.toHaveProperty("notes");
    const empty = await patch<SecretView>(secretPath(NAS), { username: "  " });
    expect(empty.body).not.toHaveProperty("username");
  });

  it("replaces the value and bumps value_updated_at", async () => {
    const before = (await get<SecretView>(secretPath(NAS))).body;
    const answer = await patch<SecretView>(secretPath(NAS), { value: "example-new-pass" });
    expect(answer.status).toBe(200);
    expect(secretValue(NAS)).toBe("example-new-pass");
    expect(Date.parse(answer.body.value_updated_at)).toBeGreaterThan(Date.parse(before.value_updated_at));
    expect(answer.body.updated_at).toBe(answer.body.value_updated_at);
    expect(auditOf("vault.secret.replace")).toHaveLength(1);
    expect(auditOf("vault.secret.update")).toHaveLength(0);
    expect(JSON.stringify(audit.records)).not.toContain("example-new-pass");
    expect(JSON.stringify(answer.body)).not.toContain("example-new-pass");
  });

  it("changes nothing when nothing changes", async () => {
    const before = (await get<SecretView>(secretPath(NAS))).body;
    const events = secretEvents().length;
    const answer = await patch<SecretView>(secretPath(NAS), { name: "nas admin", tags: ["ssh"], kind: "password" });
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual(before);
    expect(secretEvents()).toHaveLength(events);
    expect(await patch(secretPath(NAS), {})).toMatchObject({ status: 200 });
  });

  it("checks the values", async () => {
    expect(expectProblem(await patch(secretPath(NAS), { name: "" }), 422, "vault.secret.invalid").params.field).toBe("name");
    expect(expectProblem(await patch(secretPath(NAS), { tags: ["no way"] }), 422, "vault.secret.invalid").params.field).toBe("tags");
    expect(expectProblem(await patch(secretPath(NAS), { value: "" }), 422, "vault.secret.invalid").params.field).toBe("value");
    expect(expectProblem(await patch(secretPath(NAS), { username: "u".repeat(257) }), 422, "vault.secret.invalid").params.field).toBe("username");
    expectProblem(await patch(secretPath(NAS), { colour: "red" }), 400, "sys.invalid_request");
    expectProblem(await patch(secretPath(NAS), { kind: "colour" }), 400, "sys.invalid_request");
    expectProblem(await patch(secretPath(UNKNOWN_ID), { name: "x" }), 404, "vault.secret.not_found");
    expect((await get<SecretView>(secretPath(NAS))).body.name).toBe("nas admin");
  });
});

// ---------------------------------------------------------------------------------
// Delete and references

describe("delete", () => {
  it("is refused while a host binds the secret", async () => {
    const problem = expectProblem(await del(secretPath(NAS)), 409, "vault.secret.in_use");
    expect(problem.params).toEqual({ hosts: "1", connectors: "0" });
    expect(problem.title).toBe("Secret in use");
    expect(await names("")).toContain("nas admin");
    // In use wins over a stale revision, like on the server.
    expectProblem(await del(secretPath(NAS), { headers: { "If-Match": '"1"' } }), 409, "vault.secret.in_use");
  });

  it("deletes an unbound secret, with an event and an audit record", async () => {
    const stale = expectProblem(await del(secretPath(UNIFI), { headers: { "If-Match": '"1"' } }), 409, "vault.secret.conflict");
    expect(stale.params.expected).toBe("1");
    const current = (await get<SecretView>(secretPath(UNIFI))).body;
    const answer = await del(secretPath(UNIFI), { headers: { "If-Match": etagOf(current.revision ?? undefined) } });
    expect(answer.status).toBe(204);
    expect(answer.body).toBeUndefined();
    expectProblem(await get(secretPath(UNIFI)), 404, "vault.secret.not_found");
    expect(await names("")).toEqual(["nas admin"]);
    expect(secretEvents().at(-1)?.data.deleted).toEqual([{ kind: "secret", id: UNIFI }]);
    expect(auditOf("vault.secret.delete").at(-1)?.draft.details?.context).toEqual({ name: "unifi api" });
    expectProblem(await del(secretPath(UNIFI)), 404, "vault.secret.not_found");
  });

  it("works once the last host let go of the secret", async () => {
    const unbound = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), { credentials: [] });
    expect(unbound.status).toBe(200);
    expect(unbound.body.items).toEqual([]);
    expect((await del(secretPath(NAS))).status).toBe(204);
    expect(await names("")).toEqual(["unifi api"]);
  });
});

describe("references", () => {
  it("lists the hosts that bind a secret, with their names", async () => {
    const answer = await get<S["SecretReferences"]>(`${secretPath(NAS)}/references`);
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual({
      id: NAS,
      hosts: [{ host: NAS_HOST, name: "nas", role: "admin", deleted: false }],
      connectors: [],
    });
    expect((await get<S["SecretReferences"]>(`${secretPath(UNIFI)}/references`)).body).toEqual({
      id: UNIFI,
      hosts: [],
      connectors: [],
    });
  });

  it("marks a deleted host and leaves out the name of a host IPAM does not know", async () => {
    bindSecret(HOST_IDS["old-printer"] as string, UNIFI, "web");
    bindSecret(UNKNOWN_ID, UNIFI, "other");
    const answer = await get<S["SecretReferences"]>(`${secretPath(UNIFI)}/references`);
    expect(answer.body.hosts).toEqual([
      { host: UNKNOWN_ID, role: "other", deleted: false },
      { host: HOST_IDS["old-printer"], name: "old-printer", role: "web", deleted: true },
    ]);
  });

  it("answers 404 for an unknown secret", async () => {
    expectProblem(await get(`${secretPath(UNKNOWN_ID)}/references`), 404, "vault.secret.not_found");
  });
});

// ---------------------------------------------------------------------------------
// Reveal

describe("reveal", () => {
  it("returns the value once, with no-store, and remembers who looked", async () => {
    const before = (await get<SecretView>(secretPath(NAS))).body;
    const answer = await post<S["RevealedSecret"]>(revealPath(NAS), { host: NAS_HOST, reason: "Replace the disk" });
    expect(answer.status).toBe(200);
    expect(answer.res.headers.get("cache-control")).toBe("no-store");
    expect(answer.body).toEqual({
      id: NAS,
      value: SEED_SECRET_VALUES.nasAdmin,
      username: "admin",
      kind: "password",
      revealed_at: expect.any(String),
      clear_after_secs: 30,
    });
    const after = (await get<SecretView>(secretPath(NAS))).body;
    expect(after.last_revealed).toEqual({
      at: answer.body.revealed_at,
      user: ALEX_ID,
      user_name: "alex",
      host: NAS_HOST,
    });
    // A reveal moves no revision: the next edit does not hit a conflict.
    expect(after.revision).toBe(before.revision);
    const event = secretEvents().at(-1);
    expect(event?.data.objects).toEqual([{ kind: "secret", id: NAS }]);
    expect(event?.data.tables).toEqual(["vault.reveals"]);
  });

  it("audits the reveal with the host and the reason, never the value", async () => {
    const answer = await post<S["RevealedSecret"]>(revealPath(NAS), { host: NAS_HOST, reason: "  Replace the disk " });
    const [record, ...rest] = revealsOf(NAS);
    expect(rest).toEqual([]);
    expect(record?.draft.outcome).toEqual({ kind: "success" });
    expect(record?.draft.objects).toEqual([
      { kind: "secret", id: NAS },
      { kind: "host", id: NAS_HOST },
    ]);
    expect(record?.draft.details?.context).toEqual({
      kind: "password",
      name: "nas admin",
      host: NAS_HOST,
      reason: "Replace the disk",
    });
    expect(record?.at).toBe(answer.body.revealed_at);
    expect(record?.principal).toMatchObject({ kind: "user", id: ALEX_ID });
    expect(JSON.stringify(audit.records)).not.toContain(SEED_SECRET_VALUES.nasAdmin);
  });

  it("takes an empty body and returns no user name for a secret without one", async () => {
    const answer = await post<S["RevealedSecret"]>(revealPath(UNIFI));
    expect(answer.status).toBe(200);
    expect(answer.body).not.toHaveProperty("username");
    expect(answer.body).toMatchObject({ value: SEED_SECRET_VALUES.unifiApi, kind: "api_key" });
    expect(revealsOf(UNIFI)[0]?.draft.details?.context).toEqual({ kind: "api_key", name: "unifi api" });
    const stamp = (await get<SecretView>(secretPath(UNIFI))).body.last_revealed;
    expect(stamp).not.toHaveProperty("host");
  });

  it("answers 404 for an unknown secret and 400 for a bad body", async () => {
    expectProblem(await post(revealPath(UNKNOWN_ID)), 404, "vault.secret.not_found");
    expectProblem(await post(revealPath("nothing")), 400, "sys.invalid_request");
    expectProblem(await post(revealPath(NAS), { host: "nas" }), 400, "sys.invalid_request");
    expectProblem(await post(revealPath(NAS), { colour: "red" }), 400, "sys.invalid_request");
    expect(revealsOf(NAS)).toEqual([]);
  });

  it("checks the reason and audits the refusal without it", async () => {
    const problem = expectProblem(await post(revealPath(NAS), { reason: "r".repeat(201) }), 422, "vault.secret.invalid");
    expect(problem.params.field).toBe("reason");
    expect(expectProblem(await post(revealPath(NAS), { reason: "bell\u0007" }), 422, "vault.secret.invalid").params.field).toBe("reason");
    const records = revealsOf(NAS);
    expect(records).toHaveLength(2);
    expect(records[0]?.draft.outcome).toEqual({ kind: "denied" });
    expect(records[0]?.draft.details?.context).toEqual({ code: "vault.secret.invalid" });
    expect((await post(revealPath(NAS), { reason: "r".repeat(200) })).status).toBe(200);
  });

  it("refuses a viewer and audits it", async () => {
    await loginAs("robin");
    expectProblem(await post(revealPath(NAS)), 403, "auth.forbidden");
    const [record] = revealsOf(NAS);
    expect(record?.draft.outcome).toEqual({ kind: "denied" });
    expect(record?.draft.details?.context).toEqual({ code: "auth.forbidden" });
    expect(record?.principal).toMatchObject({ kind: "user", id: MOCK_USER_IDS.robin });
  });

  it("refuses a session of PIN strength with required = password", async () => {
    setPolicy("session");
    const session = db.sessions.find((s) => s.id === db.currentSessionId);
    if (session) session.strength = "pin";
    const problem = expectProblem(await post(revealPath(NAS)), 403, "auth.step_up_required");
    expect(problem.params.required).toBe("password");
    expect(problem.title).toBe("Fresh authentication required");
    expect(revealsOf(NAS)[0]?.draft.details?.context).toEqual({ code: "auth.step_up_required" });
  });

  describe("the policy session", () => {
    beforeEach(() => setPolicy("session"));

    it("passes however old the session is", async () => {
      ageCurrentSession(3 * 24 * 3600);
      expect((await post(revealPath(NAS))).status).toBe(200);
    });

    it("lets a session of password strength reveal", async () => {
      await loginAs("sam");
      ageCurrentSession(3600);
      expect((await post(revealPath(NAS))).status).toBe(200);
    });
  });

  describe("the policy fresh", () => {
    beforeEach(() => setPolicy("fresh"));

    it("passes within five minutes and fails after them", async () => {
      ageCurrentSession(299);
      expect((await post(revealPath(NAS))).status).toBe(200);
      ageCurrentSession(2);
      const problem = expectProblem(await post(revealPath(NAS)), 403, "auth.step_up_required");
      expect(problem.params.required).toBe("fresh");
      const refusals = revealsOf(NAS).filter((r) => r.draft.outcome.kind === "denied");
      expect(refusals).toHaveLength(1);
      expect(refusals[0]?.draft.details?.context).toEqual({ code: "auth.step_up_required" });
      expect((await get<SecretView>(secretPath(NAS))).body.last_revealed?.user).toBe(ALEX_ID);
    });

    it("is the default of the Standard profile", async () => {
      db.settings.secret_reveal = null;
      expect(db.settings.profile).toBe("standard");
      ageCurrentSession(600);
      expectProblem(await post(revealPath(NAS)), 403, "auth.step_up_required");
    });
  });

  describe("the policy passkey", () => {
    beforeEach(() => setPolicy("passkey"));

    it("passes a fresh passkey session and fails an old one", async () => {
      expect((await post(revealPath(NAS))).status).toBe(200);
      ageCurrentSession(301);
      const problem = expectProblem(await post(revealPath(NAS)), 403, "auth.step_up_required");
      expect(problem.params.required).toBe("passkey");
    });

    it("fails a session that signed in with a password", async () => {
      await loginAs("sam");
      const problem = expectProblem(await post(revealPath(NAS)), 403, "auth.step_up_required");
      expect(problem.params.required).toBe("passkey");
    });

    it("passes a hardware key", async () => {
      const session = db.sessions.find((s) => s.id === db.currentSessionId);
      if (session) session.strength = "hardware_key";
      expect((await post(revealPath(NAS))).status).toBe(200);
    });
  });

  describe("the host in view", () => {
    it("is required when the policy reveals bound secrets only", async () => {
      setPolicy("session", true);
      const problem = expectProblem(await post(revealPath(NAS)), 403, "vault.reveal.host_required");
      expect(problem.title).toBe("Reveal not allowed here");
      expect(revealsOf(NAS)[0]?.draft.details?.context).toEqual({ code: "vault.reveal.host_required" });
      expect((await post(revealPath(NAS), { host: NAS_HOST })).status).toBe(200);
    });

    it("must be bound to the secret, whatever the policy", async () => {
      for (const boundOnly of [false, true]) {
        setPolicy("session", boundOnly);
        const pve = HOST_IDS.pve1 as string;
        expectProblem(await post(revealPath(NAS), { host: pve }), 403, "vault.reveal.not_bound");
        expectProblem(await post(revealPath(UNIFI), { host: NAS_HOST }), 403, "vault.reveal.not_bound");
        expectProblem(await post(revealPath(NAS), { host: UNKNOWN_ID }), 403, "vault.reveal.not_bound");
      }
      const refusal = revealsOf(NAS)[0];
      expect(refusal?.draft.outcome).toEqual({ kind: "denied" });
      expect(refusal?.draft.details?.context).toEqual({ code: "vault.reveal.not_bound", host: HOST_IDS.pve1 });
      expect((await get<SecretView>(secretPath(NAS))).body.last_revealed).toBeUndefined();
    });

    it("follows the profile: Hardened wants a passkey and the host", async () => {
      db.settings.secret_reveal = null;
      const switched = await patch(`${V}/settings/security`, { profile: "hardened" });
      expect(switched.status).toBe(200);
      expectProblem(await post(revealPath(NAS)), 403, "vault.reveal.host_required");
      expect((await post(revealPath(NAS), { host: NAS_HOST })).status).toBe(200);
      ageCurrentSession(301);
      expect(expectProblem(await post(revealPath(NAS), { host: NAS_HOST }), 403, "auth.step_up_required").params.required).toBe(
        "passkey",
      );
    });

    it("follows the profile: Home needs nothing but a session", async () => {
      db.settings.secret_reveal = null;
      expect((await patch(`${V}/settings/security`, { profile: "home" })).status).toBe(200);
      ageCurrentSession(24 * 3600);
      expect((await post(revealPath(NAS))).status).toBe(200);
    });
  });

  describe("the rate limit", () => {
    it("stops the person after the limit, with Retry-After", async () => {
      mockSecrets.revealLimit = 3;
      for (let i = 0; i < 3; i += 1) expect((await post(revealPath(NAS))).status).toBe(200);
      const limited = await post(revealPath(NAS));
      const problem = expectProblem(limited, 429, "vault.reveal.rate_limited");
      const wait = Number(problem.params.retry_after);
      expect(wait).toBeGreaterThanOrEqual(1);
      expect(wait).toBeLessThanOrEqual(60);
      expect(limited.res.headers.get("retry-after")).toBe(problem.params.retry_after);
      // The server does not audit the refusal of the rate limit.
      expect(revealsOf(NAS)).toHaveLength(3);
      expect((await get<SecretView>(secretPath(NAS))).body.last_revealed?.user).toBe(ALEX_ID);
    });

    it("counts each person on their own and lets a minute pass", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      mockSecrets.revealLimit = 1;
      expect((await post(revealPath(NAS))).status).toBe(200);
      expectProblem(await post(revealPath(UNIFI)), 429, "vault.reveal.rate_limited");
      vi.setSystemTime(Date.now() + 59_000);
      expectProblem(await post(revealPath(UNIFI)), 429, "vault.reveal.rate_limited");
      vi.setSystemTime(Date.now() + 2_000);
      expect((await post(revealPath(UNIFI))).status).toBe(200);
      await loginAs("sam");
      expect((await post(revealPath(NAS))).status).toBe(200);
    });

    it("does not count a refused reveal", async () => {
      mockSecrets.revealLimit = 1;
      expectProblem(await post(revealPath(NAS), { host: UNKNOWN_ID }), 403, "vault.reveal.not_bound");
      expect((await post(revealPath(NAS))).status).toBe(200);
    });
  });
});

// ---------------------------------------------------------------------------------
// Credentials of a host

describe("host credentials", () => {
  it("lists the credentials with the version as ETag", async () => {
    const answer = await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST));
    expect(answer.status).toBe(200);
    expect(answer.res.headers.get("etag")).toBe('"1"');
    expect(answer.body.host).toBe(NAS_HOST);
    expect(answer.body.version).toBe(1);
    expect(answer.body.items).toHaveLength(1);
    expect(answer.body.items[0]).toMatchObject({ role: "admin", secret: { id: NAS, name: "nas admin" } });
    expect(Date.parse(answer.body.items[0]?.bound_at ?? "")).toBeLessThan(Date.now());
    const empty = await get<S["HostCredentialsView"]>(credentialsPath(HOST_IDS.pve1 as string));
    expect(empty.body).toEqual({ host: HOST_IDS.pve1, items: [], version: 0 });
    expect(empty.res.headers.get("etag")).toBe('"0"');
  });

  it("orders them by role, then name ignoring case", async () => {
    const web = seedSecret({ name: "Web console" });
    const zed = seedSecret({ name: "zed" });
    const alpha = seedSecret({ name: "alpha" });
    bindSecret(NAS_HOST, web.id, "web");
    bindSecret(NAS_HOST, zed.id, "admin");
    bindSecret(NAS_HOST, alpha.id, "admin");
    const answer = await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST));
    expect(answer.body.items.map((i) => [i.role, i.secret.name])).toEqual([
      ["admin", "alpha"],
      ["admin", "nas admin"],
      ["admin", "zed"],
      ["web", "Web console"],
    ]);
  });

  it("answers 404 ipam.not_found for a host IPAM does not know", async () => {
    const problem = expectProblem(await get(credentialsPath(UNKNOWN_ID)), 404, "ipam.not_found");
    expect(problem.params).toMatchObject({ kind: "host", id: UNKNOWN_ID });
    expectProblem(await put(credentialsPath(UNKNOWN_ID), { credentials: [] }), 404, "ipam.not_found");
    expectProblem(await get(credentialsPath("nothing")), 400, "sys.invalid_request");
  });

  it("binds and unbinds, raises the version and lets the secrets follow", async () => {
    const before = (await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST))).body;
    const answer = await put<S["HostCredentialsView"]>(
      credentialsPath(NAS_HOST),
      {
        credentials: [
          { secret: NAS, role: "admin" },
          { secret: UNIFI, role: "web" },
        ],
      },
      { headers: { "If-Match": '"1"' } },
    );
    expect(answer.status).toBe(200);
    expect(answer.body.version).toBe(2);
    expect(answer.res.headers.get("etag")).toBe('"2"');
    expect(answer.body.items.map((i) => [i.role, i.secret.name])).toEqual([
      ["admin", "nas admin"],
      ["web", "unifi api"],
    ]);
    // The binding that did not change keeps its time.
    expect(answer.body.items[0]?.bound_at).toBe(before.items[0]?.bound_at);
    expect((await get<SecretView>(secretPath(UNIFI))).body.hosts).toEqual([{ host: NAS_HOST, role: "web" }]);
    expect(await names(`?host=${NAS_HOST}`)).toEqual(["nas admin", "unifi api"]);

    const event = secretEvents().at(-1);
    expect(event?.data.objects).toEqual([
      { kind: "host", id: NAS_HOST },
      { kind: "secret", id: UNIFI },
    ]);
    expect(event?.data.tables).toEqual(["vault.host_bindings"]);
    const record = auditOf("vault.host.credentials").at(-1);
    expect(record?.draft.details?.changes).toEqual([
      { object: { kind: "secret", id: UNIFI }, field: "role", old: null, new: "web" },
    ]);
  });

  it("changes a role and removes a binding", async () => {
    const changed = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), {
      credentials: [{ secret: NAS, role: "ssh" }],
    });
    expect(changed.body.version).toBe(2);
    expect(changed.body.items.map((i) => i.role)).toEqual(["ssh"]);
    const removed = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), { credentials: [] });
    expect(removed.body).toMatchObject({ version: 3, items: [] });
    expect((await get<SecretView>(secretPath(NAS))).body.hosts).toEqual([]);
    const changes = auditOf("vault.host.credentials").flatMap((r) => r.draft.details?.changes ?? []);
    expect(changes.map((c) => [c.old, c.new])).toEqual([
      ["admin", "ssh"],
      ["ssh", null],
    ]);
  });

  it("keeps the version when the set does not change", async () => {
    const events = secretEvents().length;
    const answer = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), {
      credentials: [{ secret: NAS, role: "admin" }],
    });
    expect(answer.status).toBe(200);
    expect(answer.body.version).toBe(1);
    expect(secretEvents()).toHaveLength(events);
  });

  it("refuses a stale version", async () => {
    bindSecret(NAS_HOST, UNIFI, "web");
    const problem = expectProblem(
      await put(credentialsPath(NAS_HOST), { credentials: [] }, { headers: { "If-Match": '"1"' } }),
      409,
      "vault.host_credentials.conflict",
    );
    expect(problem.params).toEqual({ expected: "1", actual: "2" });
    expect((await get<S["HostCredentialsView"]>(credentialsPath(NAS_HOST))).body.items).toHaveLength(2);
    const ok = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), { credentials: [] }, { headers: { "If-Match": '"2"' } });
    expect(ok.body.version).toBe(3);
  });

  it("refuses a secret that does not exist", async () => {
    const problem = expectProblem(
      await put(credentialsPath(NAS_HOST), { credentials: [{ secret: UNKNOWN_ID, role: "admin" }] }),
      422,
      "vault.host_credentials.secret_missing",
    );
    expect(problem.params.secret).toBe(UNKNOWN_ID);
    expect(problem.errors?.[0]?.field).toBe("credentials");
  });

  it("allows one entry per secret and at most 32", async () => {
    const twice = expectProblem(
      await put(credentialsPath(NAS_HOST), {
        credentials: [
          { secret: NAS, role: "admin" },
          { secret: NAS, role: "ssh" },
        ],
      }),
      422,
      "vault.secret.invalid",
    );
    expect(twice.params.field).toBe("credentials");
    const secrets = Array.from({ length: 33 }, () => seedSecret({ name: "bulk" }).id);
    const many = expectProblem(
      await put(credentialsPath(NAS_HOST), { credentials: secrets.map((secret) => ({ secret, role: "other" })) }),
      422,
      "vault.secret.invalid",
    );
    expect(many.params.field).toBe("credentials");
    const exact = await put<S["HostCredentialsView"]>(credentialsPath(NAS_HOST), {
      credentials: secrets.slice(0, 32).map((secret) => ({ secret, role: "other" })),
    });
    expect(exact.body.items).toHaveLength(32);
  });

  it("refuses a malformed body", async () => {
    expectProblem(await put(credentialsPath(NAS_HOST), {}), 400, "sys.invalid_request");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [{ secret: NAS, role: "boss" }] }), 400, "sys.invalid_request");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [{ secret: "nas", role: "admin" }] }), 400, "sys.invalid_request");
    expectProblem(await put(credentialsPath(NAS_HOST), { credentials: [], extra: true }), 400, "sys.invalid_request");
  });
});

// ---------------------------------------------------------------------------------
// Remote hand-off

describe("remote hand-off", () => {
  interface Handoff {
    uri: string;
    host: string;
    port: number;
    username?: string;
  }

  it("answers an .rdp file with the bound user name", async () => {
    const answer = await get<string>(remotePath(NAS_HOST, "protocol=rdp"));
    expect(answer.status).toBe(200);
    expect(answer.res.headers.get("content-type")).toBe("application/x-rdp");
    expect(answer.res.headers.get("content-disposition")).toBe('attachment; filename="nas.rdp"');
    expect(answer.body).toBe(rdpFile({ address: "nas.example.test", port: 3389, username: "admin" }));
    expect(answer.body).not.toContain(SEED_SECRET_VALUES.nasAdmin);
  });

  it("answers the ssh URI as JSON", async () => {
    const answer = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh"));
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual({ uri: "ssh://admin@nas.example.test", host: "nas.example.test", port: 22, username: "admin" });
    const port = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh&port=2222"));
    expect(port.body).toEqual({ uri: "ssh://admin@nas.example.test:2222", host: "nas.example.test", port: 2222, username: "admin" });
    const rdp = await get<string>(remotePath(NAS_HOST, "protocol=rdp&port=3390"));
    expect(rdp.body).toContain("full address:s:nas.example.test:3390");
  });

  it("takes the user name from the credential of the role, else admin, else the query", async () => {
    const rdp = seedSecret({ name: "nas rdp", username: "rdpuser" });
    const noName = seedSecret({ name: "nas web" });
    bindSecret(NAS_HOST, rdp.id, "rdp");
    bindSecret(NAS_HOST, noName.id, "ssh");
    expect((await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh"))).body.username).toBe("admin");
    expect((await get<string>(remotePath(NAS_HOST, "protocol=rdp"))).body).toContain("username:s:rdpuser");
    const given = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh&user=ops"));
    expect(given.body).toMatchObject({ uri: "ssh://ops@nas.example.test", username: "ops" });
  });

  it("has no user name for a host without credentials", async () => {
    const answer = await get<Handoff>(remotePath(HOST_IDS.pve1 as string, "protocol=ssh"));
    expect(answer.body).toEqual({ uri: "ssh://pve1.example.test", host: "pve1.example.test", port: 22 });
    const rdp = await get<string>(remotePath(HOST_IDS.pve1 as string, "protocol=rdp"));
    expect(rdp.body).not.toContain("username");
  });

  it("never tells a viewer a bound user name", async () => {
    await loginAs("robin");
    const ssh = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh"));
    expect(ssh.status).toBe(200);
    expect(ssh.body).toEqual({ uri: "ssh://nas.example.test", host: "nas.example.test", port: 22 });
    const rdp = await get<string>(remotePath(NAS_HOST, "protocol=rdp"));
    expect(rdp.body).not.toContain("username");
    expect((await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh&user=ops"))).body.username).toBe("ops");
  });

  it("connects to an address of the host as given", async () => {
    const gw = HOST_IDS.gw as string;
    const v4 = await get<Handoff>(remotePath(gw, "protocol=ssh&address=192.0.2.1"));
    expect(v4.body.host).toBe("192.0.2.1");
    const v6 = await get<Handoff>(remotePath(gw, "protocol=ssh&address=2001:db8:0:10:0:0:0:1"));
    expect(v6.body).toMatchObject({ host: "2001:db8:0:10::1", uri: "ssh://[2001:db8:0:10::1]" });
    const rdp = await get<string>(remotePath(gw, "protocol=rdp&address=2001:db8:0:10::1"));
    expect(rdp.body).toContain("full address:s:[2001:db8:0:10::1]:3389");
    expect((await get<Handoff>(remotePath(gw, "protocol=ssh"))).body.host).toBe("gw.example.test");
  });

  it("connects to a DNS name of the host as sent, ignoring case and a trailing dot", async () => {
    const plain = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh&address=nas.example.test"));
    expect(plain.body.host).toBe("nas.example.test");
    const mixed = await get<Handoff>(remotePath(NAS_HOST, "protocol=ssh&address=NAS.Example.Test."));
    expect(mixed.body).toMatchObject({ host: "NAS.Example.Test", uri: "ssh://admin@NAS.Example.Test" });
    const rdp = await get<string>(remotePath(NAS_HOST, "protocol=rdp&address=Nas.example.test."));
    expect(rdp.body).toContain("full address:s:Nas.example.test:3389");
  });

  it("refuses an address or name that is not the host's", async () => {
    for (const address of ["192.0.2.12", "ha.example.test", "nas", "nas.example.test..", "nas.example.net", "2001:db8::1", "%20"]) {
      const problem = expectProblem(
        await get(remotePath(NAS_HOST, `protocol=ssh&address=${address}`)),
        422,
        "remote.address_unknown",
      );
      expect(problem.params.field).toBe("address");
      expect(problem.errors?.[0]).toMatchObject({ field: "address", code: "remote.address_unknown" });
    }
  });

  it("narrows to an interface", async () => {
    const ok = await get<Handoff>(remotePath(NAS_HOST, `protocol=ssh&interface=${INTERFACE_IDS.nas}`));
    expect(ok.body.host).toBe("nas.example.test");
    const problem = expectProblem(
      await get(remotePath(NAS_HOST, `protocol=ssh&interface=${INTERFACE_IDS.gw}`)),
      422,
      "remote.interface_unknown",
    );
    expect(problem.params.field).toBe("interface");
    expectProblem(
      await get(remotePath(NAS_HOST, `protocol=ssh&interface=${INTERFACE_IDS.nas}&address=192.0.2.1`)),
      422,
      "remote.address_unknown",
    );
  });

  it("falls back to the host name when the host has no live address", async () => {
    const gone = HOST_IDS["old-printer"] as string;
    expect((await get<Handoff>(remotePath(gone, "protocol=ssh"))).body.host).toBe("old-printer");
  });

  it("refuses a bad query", async () => {
    const bad = [
      "",
      "protocol=ftp",
      "protocol=rdp&protocol=ssh",
      "protocol=ssh&port=0",
      "protocol=ssh&port=65536",
      "protocol=ssh&port=abc",
      "protocol=ssh&port=-1",
      "protocol=ssh&interface=eth0",
      `protocol=ssh&user=${"u".repeat(257)}`,
      "protocol=ssh&colour=blue",
    ];
    for (const query of bad) expectProblem(await get(remotePath(NAS_HOST, query)), 400, "sys.invalid_query");
    expect((await get(remotePath(NAS_HOST, "protocol=ssh&port=65535"))).status).toBe(200);
    expect((await get(remotePath(NAS_HOST, "protocol=ssh&port=1"))).status).toBe(200);
  });

  it("answers 404 for an unknown host and 400 for a bad id", async () => {
    expectProblem(await get(remotePath(UNKNOWN_ID, "protocol=ssh")), 404, "ipam.not_found");
    expectProblem(await get(remotePath("nothing", "protocol=ssh")), 400, "sys.invalid_request");
  });
});
