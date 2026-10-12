// The controller cluster, the quorum gate and the local queue of the mock API, through `fetch`
// against the msw server, with the seed of cluster-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { ClusterView, DigestReport, QueuedChangeList, QueueItemView, QueueList, ReapplyResult, StepDown } from "../../cluster/model";
import { startSession } from "./auth";
import { CLUSTER_IDS, clusterState, mockCluster } from "./cluster-store";
import { findUserByName, resetMockDb, subscribeEvents, type MockEvent } from "./db";
import { MOCK_VERSION } from "./fixtures";

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
const { leader: LEADER, voterA, voterB, learner } = CLUSTER_IDS;
const ADDRESS = `/addresses/${CLUSTER_IDS.address}`;

/** Signs sam in with the given role instead of alex. */
function signInSamAs(role: "viewer" | "operator"): void {
  const sam = findUserByName("sam");
  if (!sam) throw new Error("the mock has no sam");
  sam.roles = [role];
  startSession(sam, "passkey");
}

function listen(): { events: MockEvent[]; stop: () => void } {
  const events: MockEvent[] = [];
  const stop = subscribeEvents((event) => {
    if (event.topic === "cluster") events.push(event);
  });
  return { events, stop };
}

/** Queues a patch of an address; the quorum must be lost already. */
function queueAddress(body: unknown = { address: "192.0.2.50", comment: "moved" }): Promise<Answer<QueueItemView>> {
  return post<QueueItemView>(`${V}/queue`, { method: "PATCH", path: ADDRESS, body });
}

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("GET /cluster/members", () => {
  it("lists the seed by node id", async () => {
    const answer = await get<ClusterView>(`${V}/cluster/members`);
    expect(answer.status).toBe(200);
    const view = answer.body;
    expect(view).toMatchObject({ node: LEADER, term: 7, leader: LEADER, changing: false, quorum: { state: "healthy" } });
    expect(view.members.map((m) => [m.node, m.role, m.leader, m.lag_entries ?? null])).toEqual([
      [LEADER, "voter", true, null],
      [voterA, "voter", false, 0],
      [voterB, "voter", false, 2],
      [learner, "learner", false, 4200],
    ]);
    expect(view.members[0]).toMatchObject({ name: "ctl-1.example.test", address: "192.0.2.11:8444", version: MOCK_VERSION });
    expect(view.members[3]).toMatchObject({ address: "198.51.100.14:8444", last_contact_ms: 300 });
  });

  it("is one single member in a fresh installation", async () => {
    resetMockDb("setup");
    const state = clusterState();
    expect(state.quorum.state).toBe("single");
    expect([...state.members.keys()]).toEqual([LEADER]);
  });

  it("needs a session", async () => {
    resetMockDb("signed-out");
    const answer = await get<Problem>(`${V}/cluster/members`);
    expect(answer.status).toBe(401);
    expect(answer.body.code).toBe("auth.unauthenticated");
  });
});

describe("membership changes", () => {
  it("refuses to promote a learner that is still catching up, and accepts it forced", async () => {
    const events = listen();
    const refused = await post<Problem>(`${V}/cluster/members/${learner}/promote`, {});
    expect(refused.status).toBe(409);
    expect(refused.body.code).toMatch(/^cluster\.member\.(even_voters|not_caught_up)$/);
    expect(clusterState().members.get(learner)?.role).toBe("learner");
    const forced = await post<ClusterView>(`${V}/cluster/members/${learner}/promote`, { force: true });
    events.stop();
    expect(forced.status).toBe(200);
    expect(forced.body.job_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(forced.body.members.find((m) => m.node === learner)?.role).toBe("voter");
    expect(events.events.map((e) => e.data.tables)).toEqual([["cluster.members"]]);
  });

  it("replaces a voter in the same change", async () => {
    const answer = await post<ClusterView>(`${V}/cluster/members/${learner}/promote`, { force: true, replace: voterB });
    expect(answer.status).toBe(200);
    expect(answer.body.members.map((m) => m.node)).toEqual([LEADER, voterA, learner]);
    resetMockDb("signed-in");
    const unknown = await post<Problem>(`${V}/cluster/members/${learner}/promote`, { force: true, replace: 4242 });
    expect(unknown.status).toBe(404);
  });

  it("answers 404 for an unknown member and 409 for a voter", async () => {
    expect((await post<Problem>(`${V}/cluster/members/4242/promote`, {})).status).toBe(404);
    const voter = await post<Problem>(`${V}/cluster/members/${voterA}/promote`, {});
    expect(voter.status).toBe(409);
    expect(voter.body.code).toBe("cluster.member.not_learner");
  });

  it("removes a member and refuses the last voter", async () => {
    const answer = await del<ClusterView>(`${V}/cluster/members/${learner}`);
    expect(answer.status).toBe(200);
    expect(answer.body.members.map((m) => m.node)).toEqual([LEADER, voterA, voterB]);
    expect(answer.body.job_id).toBeTruthy();
    expect((await del<Problem>(`${V}/cluster/members/${learner}`)).status).toBe(404);
    await del(`${V}/cluster/members/${voterA}`);
    await del(`${V}/cluster/members/${voterB}`);
    const last = await del<Problem>(`${V}/cluster/members/${LEADER}`);
    expect(last.status).toBe(409);
    expect(last.body.code).toBe("cluster.single");
  });

  it("hands leadership to the most caught-up voter", async () => {
    const answer = await post<StepDown>(`${V}/cluster/step-down`);
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual({ previous: LEADER, leader: voterA, term: 8 });
    const view = (await get<ClusterView>(`${V}/cluster/members`)).body;
    expect(view).toMatchObject({ term: 8, leader: voterA });
    expect(view.members.filter((m) => m.leader).map((m) => m.node)).toEqual([voterA]);
  });

  it("refuses a step-down when no other voter is caught up", async () => {
    await del(`${V}/cluster/members/${voterA}`);
    await del(`${V}/cluster/members/${voterB}`);
    const answer = await post<Problem>(`${V}/cluster/step-down`);
    expect(answer.status).toBe(409);
  });

  it("is for administrators", async () => {
    signInSamAs("operator");
    for (const [method, path] of [
      ["POST", `${V}/cluster/members/${learner}/promote`],
      ["DELETE", `${V}/cluster/members/${learner}`],
      ["POST", `${V}/cluster/step-down`],
    ] as const) {
      const answer = await call<Problem>(method, path, method === "POST" ? { json: {} } : {});
      expect(answer.status, `${method} ${path}`).toBe(403);
      expect(answer.body.code).toBe("auth.forbidden");
    }
    expect((await get<ClusterView>(`${V}/cluster/members`)).status).toBe(200);
  });
});

describe("GET /cluster/digests", () => {
  it("agrees at the current revision", async () => {
    const answer = await get<DigestReport>(`${V}/cluster/digests`);
    expect(answer.status).toBe(200);
    expect(answer.body.agree).toBe(true);
    expect(answer.body.members.map((m) => m.node)).toEqual([LEADER, voterA, voterB, learner]);
    const digests = new Set(answer.body.members.map((m) => m.sha256));
    expect(digests.size).toBe(1);
    expect([...digests][0]).toMatch(/^[0-9a-f]{64}$/);
    expect(answer.body.members.every((m) => m.revision === answer.body.revision && (m.tables ?? 0) > 0 && (m.entries ?? 0) > 0)).toBe(true);
    const named = await get<DigestReport>(`${V}/cluster/digests?revision=${answer.body.revision - 1}`);
    expect(named.body.revision).toBe(answer.body.revision - 1);
    expect((await get<Problem>(`${V}/cluster/digests?revision=x`)).status).toBe(400);
  });

  it("names the member that differs", async () => {
    mockCluster.setDigestMismatch(voterB);
    const answer = await get<DigestReport>(`${V}/cluster/digests`);
    expect(answer.body.agree).toBe(false);
    const others = answer.body.members.filter((m) => m.node !== voterB);
    expect(new Set(others.map((m) => m.sha256)).size).toBe(1);
    expect(answer.body.members.find((m) => m.node === voterB)?.sha256).not.toBe(others[0]?.sha256);
    mockCluster.setDigestMismatch(null);
    expect((await get<DigestReport>(`${V}/cluster/digests`)).body.agree).toBe(true);
  });
});

describe("the quorum gate", () => {
  it("lets writes through while the quorum holds", async () => {
    const answer = await post<Problem>(`${V}/cluster/step-down`);
    expect(answer.status).toBe(200);
  });

  it("refuses a write while isolated, with the retry time and what the queue accepts", async () => {
    mockCluster.setQuorum("isolated");
    const answer = await post<Problem>(`${V}/prefixes`, { cidr: "192.0.2.0/25" });
    expect(answer.status).toBe(503);
    expect(answer.headers.get("content-type")).toContain("application/problem+json");
    expect(answer.headers.get("retry-after")).toBe("15");
    expect(answer.body.code).toBe("cluster.no_quorum");
    expect(answer.body.params.queueable).toBe("true");
    expect(answer.body.params.state).toBe("isolated");
    expect(Number(answer.body.params.revision)).toBeGreaterThan(0);
    expect(Date.parse(answer.body.params.since ?? "")).not.toBeNaN();
    const item = await call<Problem>("PATCH", `${V}${ADDRESS}`, { json: {} });
    expect([item.status, item.body.params.queueable]).toEqual([503, "true"]);
    const bulk = await post<Problem>(`${V}/hosts/bulk`, {});
    expect([bulk.status, bulk.body.params.queueable]).toEqual([503, "true"]);
  });

  it("says a write that is no IPAM object write cannot be queued", async () => {
    mockCluster.setQuorum("electing");
    for (const path of [`${V}/cluster/step-down`, `${V}/imports`, `${V}/vlans/provision`]) {
      const answer = await post<Problem>(path, {});
      expect([answer.status, answer.body.params.queueable], path).toEqual([503, "false"]);
      expect([answer.headers.get("retry-after"), answer.body.params.state], path).toEqual(["5", "electing"]);
    }
  });

  it("lets reads, dry runs, the queue, sign-in and events through", async () => {
    mockCluster.setQuorum("isolated");
    expect((await get<ClusterView>(`${V}/cluster/members`)).status).toBe(200);
    const dry = await post<Problem>(`${V}/prefixes?dry_run=true`, { cidr: "192.0.2.0/25" });
    expect(dry.status).not.toBe(503);
    expect((await get<QueueList>(`${V}/queue`)).status).toBe(200);
    const login = await post<Problem>(`${V}/auth/login/password`, {});
    expect(login.status).not.toBe(503);
  });

  it("leaves a request without a session to the session check", async () => {
    resetMockDb("signed-out");
    mockCluster.setQuorum("isolated");
    const answer = await post<Problem>(`${V}/prefixes`, { cidr: "192.0.2.0/25" });
    expect(answer.status).toBe(401);
  });
});

describe("the local queue", () => {
  it("queues, lists and cancels a refused write", async () => {
    mockCluster.setQuorum("isolated");
    const queued = await queueAddress();
    expect(queued.status).toBe(201);
    expect(queued.body).toMatchObject({
      method: "PATCH",
      path: ADDRESS,
      queued_on: LEADER,
      state: "queued",
      summary: { action: "update", kind: "address", key: "192.0.2.50" },
      plan: { changes: [], warnings: [] },
    });
    // The API base in front of the path is accepted and dropped; the method in any case.
    const prefixed = await post<QueueItemView>(`${V}/queue`, { method: "patch", path: `${V}${ADDRESS}`, query: "acknowledge=x", body: {} });
    expect([prefixed.body.method, prefixed.body.path]).toEqual(["PATCH", ADDRESS]);
    expect((await del(`${V}/queue/${prefixed.body.id}`)).status).toBe(204);
    expect(queued.body.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(Date.parse(queued.body.expires_at) - Date.parse(queued.body.queued_at)).toBe(7 * 86_400_000);
    const created = await post<QueueItemView>(`${V}/queue`, { method: "POST", path: "/prefixes", body: { cidr: "198.51.100.0/24" } });
    expect(created.body.summary).toEqual({ action: "create", kind: "prefix", key: "198.51.100.0/24" });
    const bulk = await post<QueueItemView>(`${V}/queue`, { method: "POST", path: "/vlans/bulk", body: {} });
    expect(bulk.body.summary).toEqual({ action: "bulk", kind: "vlan" });
    const list = await get<QueueList>(`${V}/queue`);
    expect(list.body.items.map((i) => i.id)).toEqual([queued.body.id, created.body.id, bulk.body.id]);
    expect((await del(`${V}/queue/${created.body.id}`)).status).toBe(204);
    const missing = await del<Problem>(`${V}/queue/${created.body.id}`);
    expect([missing.status, missing.body.code]).toEqual([404, "queue.not_found"]);
    expect((await get<QueueList>(`${V}/queue`)).body.items).toHaveLength(2);
  });

  it("refuses to queue while the quorum holds", async () => {
    const answer = await queueAddress();
    expect(answer.status).toBe(409);
    expect((answer.body as unknown as Problem).code).toBe("queue.not_isolated");
  });

  it("refuses what the queue does not take", async () => {
    mockCluster.setQuorum("isolated");
    const other = await post<Problem>(`${V}/queue`, { method: "POST", path: "/imports", body: {} });
    expect([other.status, other.body.code]).toEqual([422, "queue.not_queueable"]);
    const method = await post<Problem>(`${V}/queue`, { method: "GET", path: "/prefixes" });
    expect([method.status, method.body.code]).toEqual([422, "queue.not_queueable"]);
    const path = await post<Problem>(`${V}/queue`, { method: "POST", path: "elsewhere" });
    expect(path.status).toBe(400);
  });
});

describe("the heal", () => {
  it("applies the whole queue without conflicts", async () => {
    mockCluster.setQuorum("isolated");
    await queueAddress();
    await queueAddress({ comment: "again" });
    mockCluster.heal({ conflicts: false });
    expect((await get<ClusterView>(`${V}/cluster/members`)).body.quorum.state).toBe("healthy");
    expect((await get<QueueList>(`${V}/queue`)).body.items).toEqual([]);
    const list = (await get<QueuedChangeList>(`${V}/queue/conflicts`)).body;
    expect(list.revision).toBeGreaterThan(0);
    expect(list.items.map((c) => c.state)).toEqual(["applied", "applied"]);
    expect(list.items.every((c) => c.settled_at && c.request.method === "PATCH" && !c.conflict)).toBe(true);
  });

  it("applies the first item and conflicts the others", async () => {
    mockCluster.setQuorum("isolated");
    await queueAddress();
    await queueAddress({ comment: "again" });
    mockCluster.heal({ conflicts: true });
    const changes = (await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items;
    expect(changes.map((c) => c.state)).toEqual(["applied", "conflict"]);
    expect(changes[1]?.conflict).toMatchObject({ code: "queue.plan_changed", status: 409 });
    expect(changes[1]?.current_plan).toBeTruthy();
  });

  it("settles an expired item as an expired record", async () => {
    mockCluster.setQuorum("isolated");
    const queued = await queueAddress();
    const stored = clusterState().queue.find((s) => s.item.id === queued.body.id);
    if (stored) stored.item.state = "expired";
    mockCluster.heal({ conflicts: false });
    const changes = (await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items;
    expect(changes.map((c) => [c.state, c.conflict?.code])).toEqual([["expired", "queue.expired"]]);
  });

  it("seeds one conflict when the queue was empty", async () => {
    mockCluster.setQuorum("isolated");
    mockCluster.heal({ conflicts: true });
    const changes = (await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items;
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ state: "conflict", summary: { action: "update", kind: "address", key: "192.0.2.50" } });
  });

  it("shows a person only their own changes", async () => {
    mockCluster.setQuorum("isolated");
    await queueAddress();
    mockCluster.heal({ conflicts: true });
    signInSamAs("operator");
    expect((await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items).toEqual([]);
    const id = clusterState().changes[0]?.change.id;
    expect((await del<Problem>(`${V}/queue/conflicts/${id}`)).status).toBe(404);
  });
});

describe("resolving a conflict", () => {
  async function conflict(): Promise<QueuedChangeList["items"][number]> {
    mockCluster.setQuorum("isolated");
    mockCluster.heal({ conflicts: true });
    const first = (await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items[0];
    if (!first) throw new Error("no conflict");
    return first;
  }

  it("previews, then re-applies", async () => {
    const change = await conflict();
    const path = `${V}/queue/conflicts/${change.id}/reapply`;
    const dry = await post<ReapplyResult>(`${path}?dry_run=true`);
    expect(dry.status).toBe(200);
    expect(dry.body).toMatchObject({ dry_run: true, warnings: [], plan: { changes: [], warnings: [] } });
    expect(clusterState().changes[0]?.change.state).toBe("conflict");
    const applied = await post<ReapplyResult>(path);
    expect(applied.status).toBe(200);
    expect(applied.body).toMatchObject({ dry_run: false, warnings: [] });
    // A re-applied change leaves the list: its record is gone.
    expect((await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items).toEqual([]);
    const again = await post<Problem>(path);
    expect([again.status, again.body.code]).toEqual([404, "queue.not_found"]);
  });

  it("discards", async () => {
    const change = await conflict();
    expect((await del(`${V}/queue/conflicts/${change.id}`)).status).toBe(204);
    expect((await get<QueuedChangeList>(`${V}/queue/conflicts`)).body.items).toEqual([]);
    expect((await del<Problem>(`${V}/queue/conflicts/${change.id}`)).status).toBe(404);
    expect((await del<Problem>(`${V}/queue/conflicts/0190d1c2-0000-7000-8000-00000c1000ff`)).body.code).toBe("queue.not_found");
  });

  it("refuses to re-apply an applied change", async () => {
    mockCluster.setQuorum("isolated");
    await queueAddress();
    mockCluster.heal({ conflicts: false });
    const applied = clusterState().changes[0]?.change;
    const again = await post<Problem>(`${V}/queue/conflicts/${applied?.id}/reapply`);
    expect([again.status, again.body.code]).toEqual([409, "queue.changed"]);
  });
});

describe("the quorum alarm", () => {
  it("is published with every change of the quorum", () => {
    const events = listen();
    mockCluster.setQuorum("isolated");
    mockCluster.setQuorum("electing");
    mockCluster.setQuorum("healthy");
    events.stop();
    const alarms = events.events.filter((e) => e.data.kind === "cluster.quorum");
    expect(alarms.map((e) => e.id)).toEqual([null, null, null]);
    expect(alarms.map((e) => e.data.params.state)).toEqual(["isolated", "electing", "healthy"]);
    const [isolated, electing, healthy] = alarms.map((e) => e.data.params);
    expect(Object.keys(isolated ?? {}).sort()).toEqual(["applied", "last_contact", "since", "state"]);
    expect(Object.keys(electing ?? {}).sort()).toEqual(["since", "state"]);
    expect(Object.keys(healthy ?? {})).toEqual(["state"]);
  });

  it("shows in the cluster view", async () => {
    mockCluster.setQuorum("isolated");
    const quorum = (await get<ClusterView>(`${V}/cluster/members`)).body.quorum;
    expect(quorum).toMatchObject({ state: "isolated" });
    expect(quorum.applied).toBeGreaterThan(0);
    expect(quorum.since).toBeTruthy();
  });
});
