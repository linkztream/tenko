// The findings counts and the `findings` topic of the mock API, through `fetch` against the msw
// server, with the seed of the signed-in scenario (documentation ranges only).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { recordAlarm, resetMockDb, subscribeEvents, type MockEvent } from "./db";
import { FINDING_AREAS, mockFindingCounts, setMockFindingsExtra, setMockHealthFindings } from "./findings-store";
import { ipamState } from "./ipam/api";
import { jobStore } from "./job-store";
import { RECONCILE_IDS, reconcileState } from "./reconcile-store";

type S = components["schemas"];

const V = "/api/v1";
const P = RECONCILE_IDS.proposal;

async function counts(): Promise<S["FindingCounts"]> {
  const res = await fetch(`${V}/findings/counts`, { headers: { accept: "application/json" } });
  expect(res.status).toBe(200);
  return (await res.json()) as S["FindingCounts"];
}

async function decide(id: string, action: "approve" | "reject", json?: unknown): Promise<void> {
  const res = await fetch(`${V}/proposals/${id}/${action}`, {
    method: "POST",
    headers: json === undefined ? {} : { "content-type": "application/json" },
    body: json === undefined ? null : JSON.stringify(json),
  });
  expect(res.status, `${action} ${id}`).toBe(200);
}

/** What the store's own state says: the open proposals, the waiting jobs and the alarms. */
function expected() {
  const open = [...reconcileState().proposals.values()].filter((p) => p.state === "open");
  const conflicts = open.filter((p) => p.kind === "conflict").length;
  const waiting = jobStore.jobs.filter(({ job }) => job.state === "waiting" && job.steps.some((s) => s.state.state === "waiting_for_manual")).length;
  const levels = [...ipamState().levels.values()];
  return {
    open: open.length,
    conflicts,
    waiting,
    critical: levels.filter((l) => l === "critical").length,
    warning: levels.filter((l) => l === "warning").length,
  };
}

let events: MockEvent[] = [];
let unsubscribe = () => {};

beforeEach(() => {
  resetMockDb("signed-in");
  events = [];
  unsubscribe = subscribeEvents((event) => {
    if (event.topic === "findings") events.push(event);
  });
});

afterEach(() => {
  unsubscribe();
  setMockFindingsExtra({});
});

describe("GET /findings/counts", () => {
  it("counts the open proposals, the waiting jobs and the alarms of the state", async () => {
    const want = expected();
    expect(want.open).toBeGreaterThan(0);
    expect(want.waiting).toBeGreaterThan(0);
    const body = await counts();
    expect(body.areas.discovery).toEqual({ act: want.conflicts, review: want.open - want.conflicts, info: 0 });
    expect(body.areas.jobs).toEqual({ act: want.waiting, review: 0, info: 0 });
    expect(body.areas.ipam).toEqual({ act: want.critical, review: want.warning, info: 0 });
    expect(body.sources).toEqual({ proposal: want.open, job: want.waiting, alarm: want.critical + want.warning, health: 0, reconcile: 0 });
    expect(body.total.act).toBe(want.conflicts + want.waiting + want.critical);
    expect(body.total.review).toBe(want.open - want.conflicts + want.warning);
    expect(body.total.info).toBe(0);
    expect(body.problems).toBe(body.total.act + body.total.review);
    expect(body.revision).toBe(mockFindingCounts().revision);
    for (const area of FINDING_AREAS) expect(body.areas[area], area).toBeDefined();
  });

  it("equals the open proposals the proposal list gives", async () => {
    const list = (await (await fetch(`${V}/proposals?state=open&limit=1000`)).json()) as { items: unknown[] };
    expect((await counts()).sources.proposal).toBe(list.items.length);
  });

  it("falls when a proposal is rejected or approved", async () => {
    const before = await counts();
    await decide(P.printerTaken, "reject", { reason: "The printer was replaced" });
    const afterReject = await counts();
    expect(afterReject.sources.proposal).toBe(before.sources.proposal - 1);
    const discovery = (c: S["FindingCounts"]) => c.areas.discovery.act + c.areas.discovery.review;
    expect(discovery(afterReject)).toBe(discovery(before) - 1);
    expect(afterReject.revision).toBeGreaterThan(before.revision);

    await decide(P.mediaPc, "approve");
    const afterApprove = await counts();
    expect(afterApprove.sources.proposal).toBe(afterReject.sources.proposal - 1);
    expect(discovery(afterApprove)).toBe(discovery(afterReject) - 1);
  });

  it("adds the extra of a test as health and clears it with a reset", async () => {
    const before = await counts();
    setMockFindingsExtra({ dns: { act: 2, info: 1 }, discovery: { review: 3 } });
    const body = await counts();
    expect(body.areas.dns).toEqual({ act: 2, review: 0, info: 1 });
    expect(body.areas.discovery.review).toBe(before.areas.discovery.review + 3);
    expect(body.sources.health).toBe(6);
    expect(body.sources.proposal).toBe(before.sources.proposal);
    expect(body.total.act).toBe(before.total.act + 2);
    expect(body.total.review).toBe(before.total.review + 3);
    expect(body.total.info).toBe(1);
    expect(body.problems).toBe(before.problems + 5);

    resetMockDb("signed-in");
    expect(await counts()).toEqual(before);
  });

  it("answers 401 without a session", async () => {
    resetMockDb("signed-out");
    const res = await fetch(`${V}/findings/counts`);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { code: string }).code).toBe("auth.unauthenticated");
  });
});

// U3: the list the start page's strip reads, counted by the counts.
describe("GET /findings", () => {
  async function list(query = ""): Promise<S["Finding"][]> {
    const res = await fetch(`${V}/findings${query}`, { headers: { accept: "application/json" } });
    expect(res.status).toBe(200);
    return ((await res.json()) as { items: S["Finding"][] }).items;
  }

  it("lists what the counts count, the findings to act on first, each with its default action", async () => {
    const all = await list("?limit=1000");
    const body = await counts();
    expect(all.length).toBe(body.total.act + body.total.review + body.total.info);
    const order = { act: 0, review: 1, info: 2 } as const;
    expect(all.map((f) => order[f.severity])).toEqual([...all.map((f) => order[f.severity])].sort((a, b) => a - b));
    const conflict = all.find((f) => f.kind === "conflict")!;
    expect(conflict.severity).toBe("act");
    expect(conflict.action).toBe("resolve");
    expect(conflict.source).toBe("proposal");
    const job = all.find((f) => f.kind === "job_waiting")!;
    expect(job.action).toBe("open_manual_step");
    expect(job.evidence.path).toBe(`/jobs/${job.evidence.id}`);
  });

  it("filters by severity, kind and source, comma separated or repeated, and caps the page", async () => {
    const acts = await list("?severity=act");
    expect(acts.length).toBe((await counts()).total.act);
    expect(acts.every((f) => f.severity === "act")).toBe(true);
    expect((await list("?kind=conflict,job_waiting")).every((f) => f.kind === "conflict" || f.kind === "job_waiting")).toBe(true);
    expect((await list("?source=job&source=alarm")).every((f) => f.source === "job" || f.source === "alarm")).toBe(true);
    expect(await list("?limit=1")).toHaveLength(1);
  });

  it("lists a health finding a test adds, and counts it", async () => {
    setMockHealthFindings([{ code: "node.disk.low", severity: "act", area: "nodes", summary: "low", params: { available: "1", total: "2" } }]);
    const health = await list("?source=health");
    expect(health.map((f) => [f.code, f.severity, f.area, f.action])).toEqual([["node.disk.low", "act", "nodes", "open_status"]]);
    expect((await counts()).areas.nodes.act).toBe(1);
  });
});

describe("the topic findings", () => {
  it("carries a findings.changed event after a decision, with the revision as a string and no id", async () => {
    const before = mockFindingCounts().revision;
    await decide(P.printerTaken, "reject", { reason: "The printer was replaced" });
    expect(events.length).toBeGreaterThan(0);
    const event = events.at(-1)!;
    expect(event.id).toBeNull();
    expect(event.data.topic).toBe("findings");
    expect(event.data.kind).toBe("findings.changed");
    expect(event.data.objects).toContainEqual({ kind: "proposal", id: P.printerTaken });
    // The revision the counts had when the event was published; a later write (the audit record) may raise it.
    expect(event.data.params.revision).toMatch(/^\d+$/);
    expect(Number(event.data.params.revision)).toBeGreaterThan(before);
    expect(Number(event.data.params.revision)).toBeLessThanOrEqual((await counts()).revision);
    expect(event.data.revision).toBeUndefined();
  });

  it("does not answer its own events", () => {
    recordAlarm("findings", { kind: "findings.changed" });
    expect(events).toHaveLength(1);
  });
});
