// Cluster nodes and enrolment tokens of the mock API, through `fetch` against the msw server,
// with the seed of nodes-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { audit } from "./audit-store";
import { startSession } from "./auth";
import { findUserByName, resetMockDb } from "./db";
import { MOCK_CA_FINGERPRINT } from "./fixtures";
import { MISMATCH_WARNING, NODE_IDS, nodeRef } from "./nodes-store";

type S = components["schemas"];
type Page<T> = { items: T[]; next_cursor?: string | null; revision: number };
interface Problem {
  code: string;
  status: number;
  params: Record<string, string>;
}
interface Answer<T> {
  status: number;
  headers: Headers;
  body: T;
}

async function call<T>(method: string, path: string, init: { json?: unknown; headers?: Record<string, string> } = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json === undefined ? null : JSON.stringify(init.json) });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: (text ? JSON.parse(text) : undefined) as T };
}
const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown) => call<T>("POST", path, { json });
const del = <T>(path: string) => call<T>("DELETE", path);

const V = "/api/v1";
const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nbW9jayByZXF1ZXN0\n-----END CERTIFICATE REQUEST-----\n";

/** Signs sam in with the given role instead of alex. */
function signInSamAs(role: "viewer" | "operator"): void {
  const sam = findUserByName("sam");
  if (!sam) throw new Error("the mock has no sam");
  sam.roles = [role];
  startSession(sam, "passkey");
}

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the node operations of the document", () => {
  const OPERATIONS = apiOperations.filter((o) => /^\/api\/v1\/nodes(\/|$)/.test(o.path));

  it("are all answered, each after the session check except the public enrolment", async () => {
    expect(OPERATIONS.length).toBe(7);
    for (const operation of OPERATIONS) {
      const path = operation.path.replace("{id}", operation.path.includes("enrolments") ? NODE_IDS.token : String(NODE_IDS.dmz));
      const json = operation.method === "get" || operation.method === "delete" ? undefined : {};
      resetMockDb("signed-in");
      expect((await call(operation.method.toUpperCase(), path, { json })).status, `${operation.method} ${operation.path}`).not.toBe(501);
      if (operation.path === "/api/v1/nodes/enrol") continue;
      resetMockDb("signed-out");
      const answer = await call<Problem>(operation.method.toUpperCase(), path, { json });
      expect(answer.status, `${operation.method} ${operation.path}`).toBe(401);
      expect(answer.body.code).toBe("auth.unauthenticated");
    }
  });
});

describe("GET /nodes", () => {
  it("lists the enrolled nodes by id with their live connection", async () => {
    const page = await get<Page<S["NodeView"]>>(`${V}/nodes`);
    expect(page.status).toBe(200);
    expect(page.body.items.map((n) => [n.id, n.name, n.connected])).toEqual([
      [NODE_IDS.dmz, "probe-dmz", true],
      [NODE_IDS.lab, "probe-lab", false],
    ]);
    const dmz = page.body.items[0]!;
    expect(dmz.address).toBe("192.0.2.20");
    expect(dmz.connection?.major).toBe(1);
    expect(page.body.items[1]?.protocol.mismatch).toMatchObject({ ours: [1], theirs: [2] });
    // One per page: the cursor reaches the second node.
    const first = await get<Page<S["NodeView"]>>(`${V}/nodes?limit=1`);
    expect(first.body.items).toHaveLength(1);
    const second = await get<Page<S["NodeView"]>>(`${V}/nodes?limit=1&cursor=${first.body.next_cursor}`);
    expect(second.body.items[0]?.id).toBe(NODE_IDS.lab);
    expect((await get<Problem>(`${V}/nodes?role=probe`)).body.code).toBe("sys.invalid_query");
  });

  it("shows one node with its ETag and refuses a malformed or unknown id", async () => {
    const one = await get<S["NodeView"]>(`${V}/nodes/${NODE_IDS.dmz}`);
    expect(one.status).toBe(200);
    expect(one.headers.get("etag")).toBe(`"${one.body.revision}"`);
    const bad = await get<Problem>(`${V}/nodes/abc`);
    expect([bad.status, bad.body.code]).toEqual([400, "sys.invalid_request"]);
    const missing = await get<Problem>(`${V}/nodes/4711`);
    expect([missing.status, missing.body.code]).toEqual([404, "cluster.node.not_found"]);
  });

  it("is readable by viewers, who may not revoke or manage tokens", async () => {
    signInSamAs("viewer");
    expect((await get<Page<S["NodeView"]>>(`${V}/nodes`)).body.items).toHaveLength(2);
    expect((await del<Problem>(`${V}/nodes/${NODE_IDS.dmz}`)).body.code).toBe("auth.forbidden");
    expect((await get<Problem>(`${V}/nodes/enrolments`)).body.code).toBe("auth.forbidden");
    expect((await post<Problem>(`${V}/nodes/enrolments`, {})).body.code).toBe("auth.forbidden");
  });
});

describe("DELETE /nodes/{id}", () => {
  it("revokes a node: it leaves the list, its name is free and the revocation is audited", async () => {
    const before = audit.records.length;
    const revoked = await del(`${V}/nodes/${NODE_IDS.lab}`);
    expect(revoked.status).toBe(204);
    expect((await get<Problem>(`${V}/nodes/${NODE_IDS.lab}`)).status).toBe(404);
    expect((await del<Problem>(`${V}/nodes/${NODE_IDS.lab}`)).body.code).toBe("cluster.node.not_found");
    const record = audit.records.slice(before).find((r) => r.draft.action === "cluster.node.revoke");
    expect(record?.draft.objects).toEqual([nodeRef(NODE_IDS.lab)]);
    // The name is free again for a new token.
    expect((await post(`${V}/nodes/enrolments`, { name: "probe-lab" })).status).toBe(201);
  });
});

describe("enrolment tokens", () => {
  it("lists the seeded pending token without its text", async () => {
    const list = await get<S["EnrolmentList"]>(`${V}/nodes/enrolments`);
    expect(list.status).toBe(200);
    expect(list.body.items.map((e) => [e.id, e.state, e.name])).toEqual([[NODE_IDS.token, "pending", "probe-garage"]]);
    expect(JSON.stringify(list.body)).not.toContain("tnk1.");
  });

  it("creates a token once, with the fingerprint and the command, and never shows it again", async () => {
    const made = await post<S["CreatedEnrolment"]>(`${V}/nodes/enrolments`, { roles: ["probe"], name: "probe-attic", expires_in_secs: 600 });
    expect(made.status).toBe(201);
    expect(made.headers.get("cache-control")).toBe("no-store");
    expect(made.body.token).toMatch(/^tnk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
    expect(made.body.token).toHaveLength(81);
    expect(made.body.ca_fingerprint).toBe(MOCK_CA_FINGERPRINT);
    expect(made.body.command).toContain(`--token ${made.body.token}`);
    expect(made.body.command).toContain(`--ca-fingerprint ${MOCK_CA_FINGERPRINT}`);
    expect(made.body.command).toMatch(/^tenko node enrol --controller https?:\/\//);
    expect(made.body.enrolment).toMatchObject({ state: "pending", roles: ["probe"], name: "probe-attic" });
    const expires = Date.parse(made.body.enrolment.expires_at) - Date.parse(made.body.enrolment.created_at);
    expect(expires).toBe(600_000);
    const list = await get<S["EnrolmentList"]>(`${V}/nodes/enrolments`);
    expect(list.body.items[0]?.id).toBe(made.body.enrolment.id);
    expect(JSON.stringify(list.body)).not.toContain(made.body.token);
    expect(audit.records.some((r) => r.draft.action === "cluster.enrolment.create")).toBe(true);
  });

  it("defaults to a probe token for an hour and refuses controllers, bad lifetimes and names", async () => {
    const plain = await post<S["CreatedEnrolment"]>(`${V}/nodes/enrolments`);
    expect(plain.status).toBe(201);
    expect(plain.body.enrolment.roles).toEqual(["probe"]);
    expect(Date.parse(plain.body.enrolment.expires_at) - Date.parse(plain.body.enrolment.created_at)).toBe(3_600_000);
    const cases: [unknown, number, string][] = [
      [{ roles: ["controller"] }, 422, "cluster.enrolment.roles"],
      [{ expires_in_secs: 5 }, 422, "cluster.enrolment.lifetime"],
      [{ expires_in_secs: 604_801 }, 422, "cluster.enrolment.lifetime"],
      [{ name: "-bad" }, 422, "cluster.node.name"],
      [{ name: "probe-dmz" }, 409, "cluster.node.name_taken"],
      [{ roles: ["router"] }, 400, "sys.invalid_request"],
      [{ colour: "blue" }, 400, "sys.invalid_request"],
    ];
    for (const [body, status, code] of cases) {
      const answer = await post<Problem>(`${V}/nodes/enrolments`, body);
      expect([answer.status, answer.body.code], JSON.stringify(body)).toEqual([status, code]);
    }
  });

  it("deletes a token whatever its state", async () => {
    expect((await del(`${V}/nodes/enrolments/${NODE_IDS.token}`)).status).toBe(204);
    expect((await get<S["EnrolmentList"]>(`${V}/nodes/enrolments`)).body.items).toEqual([]);
    expect((await del<Problem>(`${V}/nodes/enrolments/${NODE_IDS.token}`)).body.code).toBe("cluster.enrolment.not_found");
    expect((await del<Problem>(`${V}/nodes/enrolments/not-a-uuid`)).body.code).toBe("sys.invalid_request");
  });
});

describe("POST /nodes/enrol", () => {
  it("enrols a node once with a token; the token is used up", async () => {
    const made = await post<S["CreatedEnrolment"]>(`${V}/nodes/enrolments`, { roles: ["probe"] });
    const request = { token: made.body.token, csr: CSR, name: "probe-attic", address: "198.51.100.20", version: "0.1.0", majors: [1] };
    const enrolled = await post<S["EnrolResponse"]>(`${V}/nodes/enrol`, request);
    expect(enrolled.status).toBe(201);
    expect(enrolled.headers.get("cache-control")).toBe("no-store");
    expect(enrolled.body.node).toMatchObject({ id: 1003, name: "probe-attic", address: "198.51.100.20", connected: false });
    expect(enrolled.body.cluster_port).toBe(8444);
    expect(enrolled.body.ca_root).toContain("BEGIN CERTIFICATE");
    const again = await post<Problem>(`${V}/nodes/enrol`, request);
    expect([again.status, again.body.code]).toEqual([401, "cluster.enrolment.used"]);
    const list = await get<S["EnrolmentList"]>(`${V}/nodes/enrolments`);
    expect(list.body.items.find((e) => e.id === made.body.enrolment.id)).toMatchObject({ state: "used", used: { node: 1003 } });
    expect((await get<Page<S["NodeView"]>>(`${V}/nodes`)).body.items.map((n) => n.id)).toEqual([NODE_IDS.dmz, NODE_IDS.lab, 1003]);
  });

  it("refuses forged tokens, other roles, unusable requests and protocol mismatches", async () => {
    const made = await post<S["CreatedEnrolment"]>(`${V}/nodes/enrolments`, { roles: ["probe"] });
    const forged = made.body.token.slice(0, -1) + (made.body.token.endsWith("A") ? "B" : "A");
    const cases: [Record<string, unknown>, number, string][] = [
      [{ token: forged, csr: CSR }, 401, "cluster.enrolment.invalid_token"],
      [{ token: "x", csr: CSR }, 401, "cluster.enrolment.invalid_token"],
      [{ token: made.body.token, csr: CSR, roles: ["dns"] }, 403, "cluster.enrolment.roles"],
      [{ token: made.body.token, csr: "not a request" }, 422, "cluster.ca.invalid_csr"],
      [{ token: made.body.token, csr: CSR, majors: [2] }, 409, "cluster.protocol.unsupported"],
      [{ token: made.body.token }, 400, "sys.invalid_request"],
    ];
    for (const [body, status, code] of cases) {
      const answer = await post<Problem>(`${V}/nodes/enrol`, body);
      expect([answer.status, answer.body.code], JSON.stringify(body)).toEqual([status, code]);
    }
  });

  it("answers without a session", async () => {
    const made = await post<S["CreatedEnrolment"]>(`${V}/nodes/enrolments`, {});
    await post(`${V}/auth/logout`);
    const enrolled = await post<S["EnrolResponse"]>(`${V}/nodes/enrol`, { token: made.body.token, csr: CSR, name: "probe-shed" });
    expect(enrolled.status).toBe(201);
  });
});

describe("the cluster in the system status", () => {
  it("counts nodes, connections and versions and warns about the mismatched node", async () => {
    const status = await get<S["SystemStatus"]>(`${V}/system/status`);
    expect(status.body.cluster).toMatchObject({ nodes: 2, connected: 1, mismatched: 1, majors: [1], listening: ["0.0.0.0:8444"] });
    expect(Object.values(status.body.cluster?.versions ?? {})).toEqual([1]);
    const warning = status.body.warnings.find((w) => w.code === MISMATCH_WARNING);
    expect(warning?.params).toEqual({ count: "1", nodes: String(NODE_IDS.lab) });
    await del(`${V}/nodes/${NODE_IDS.lab}`);
    const after = await get<S["SystemStatus"]>(`${V}/system/status`);
    expect(after.body.cluster).toMatchObject({ nodes: 1, mismatched: 0 });
    expect(after.body.warnings.some((w) => w.code === MISMATCH_WARNING)).toBe(false);
  });

});
