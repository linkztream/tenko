// The jobs and the audit log of the mock API through `fetch`, against the msw server that
// src/app/testing/setup.ts starts.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditRecord, AuditVerifyReport, Job, JobDetail, JobSummary, ManualTask, Page } from "../types";
import {
  AUDIT_SEED_IDS,
  appendAudit,
  audit,
  principalNow,
  recordDigest,
  tamperAuditRecord,
  verifyAudit,
} from "./audit-store";
import { INITIAL_REVISION, db, resetMockDb } from "./db";
import { MOCK_USER_IDS } from "./fixtures";
import {
  KEEP_JOBS,
  MAX_NOTE_BYTES,
  MOCK_HOST_IDS,
  MOCK_JOB_IDS,
  MOCK_MOVE_GROUP,
  advanceMockJobs,
  createJob,
  findJob,
  jobStore,
  manualTask,
  moveJobInput,
  recordInlineJob,
  type MockJobInput,
} from "./job-store";

/** The target network of the seed moves: the IoT prefix of the IPAM seed. */
const MOCK_MOVE_PREFIX = "0190d1c2-0000-7000-8000-0000000a0002";

/** The arguments of every manual task of the move of thermostat-1 (crates/tenko-ipam/src/moves/preview.rs). */
const MOVE_TASK_ARGS = {
  prefix: MOCK_MOVE_PREFIX,
  cidr: "198.51.100.0/24",
  vrf: "0190d1c2-0000-7000-8000-000000020001",
  old_ip: "192.0.2.41",
  new_ip: "198.51.100.41",
  address: "0190d1c2-0000-7000-8000-0000000f0001",
  new_address: "0190d1c2-0000-7000-8000-0000000e0001",
  vlan: "0190d1c2-0000-7000-8000-00000004001e",
  vid: "30",
  host: "thermostat-1",
  mac: "00:00:5e:00:53:29",
};

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

async function call<T = unknown>(method: string, path: string, json?: unknown): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: json === undefined ? null : JSON.stringify(json) });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

/** A request with a body that is not JSON of the shape `call` sends. */
async function callRaw<T = unknown>(method: string, path: string, body: string): Promise<Answer<T>> {
  const res = await fetch(path, { method, headers: { "content-type": "application/json" }, body });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown) => call<T>("POST", path, json);

interface Problem {
  status: number;
  code: string;
  title: string;
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
  return body;
}

const HOUR = 3_600_000;
const jobPath = (id: string) => `/api/v1/jobs/${id}`;
const completePath = (id: string, index: number) => `/api/v1/jobs/${id}/steps/${index}/complete`;

async function summaryOf(id: string): Promise<JobSummary> {
  const page = await get<Page<JobSummary>>("/api/v1/jobs?limit=1000");
  const found = page.body.items.find((j) => j.id === id);
  if (!found) throw new Error(`job ${id} is not listed`);
  return found;
}

async function detailOf(id: string): Promise<JobDetail> {
  const answer = await get<JobDetail>(jobPath(id));
  expect(answer.status).toBe(200);
  return answer.body;
}

function recordOf(id: string) {
  const rec = findJob(id);
  if (!rec) throw new Error(`no job ${id}`);
  return rec;
}

/** The task of a step that waits for a person. */
function taskOf(job: Job, index: number): ManualTask | undefined {
  const state = job.steps[index]?.state;
  return state?.state === "waiting_for_manual" ? state.data.task : undefined;
}

const stateOf = (job: Job, index: number) => job.steps[index]?.state.state;

/** The arguments of the observation task of the jobs below. */
const OBSERVE_ARGS = { host: "nas", new_ip: "198.51.100.44", cidr: "198.51.100.0/24", timeout_secs: "600" };

/** A job with one automatic step and a manual step without an undo task, like a move. */
function plainJob(overrides: Partial<MockJobInput> = {}): MockJobInput {
  return {
    kind: "ipam.move",
    title: "ipam.move.title",
    targets: [{ kind: "host", id: MOCK_HOST_IDS.nas }],
    timeoutSecs: 600,
    steps: [
      { kind: "ipam.move.intent", automatic: true, summary: "ipam.move.step.intent" },
      { kind: "ipam.move.observe", automatic: false, manual: manualTask("ipam.move.observe", OBSERVE_ARGS) },
    ],
    ...overrides,
  };
}

/**
 * A job whose manual step has an undo task. The manual steps of a move have none, but the engine
 * supports them: a rollback then waits for a person to undo the step.
 */
function undoJob(overrides: Partial<MockJobInput> = {}): MockJobInput {
  const task: ManualTask = {
    instruction: "jobs.task.dhcp_reserve",
    undo: "jobs.task.dhcp_release",
    args: { host: "nas", mac: "00:00:5e:00:53:0b", ip: "198.51.100.44", prefix: "198.51.100.0/24" },
  };
  return {
    kind: "ipam.move",
    title: "ipam.move.title",
    targets: [{ kind: "host", id: MOCK_HOST_IDS.nas }],
    timeoutSecs: 600,
    steps: [
      { kind: "ipam.move.intent", automatic: true },
      { kind: "ipam.move.dhcp", automatic: false, manual: task },
      { kind: "ipam.move.l2", automatic: false, manual: manualTask("ipam.move.l2", OBSERVE_ARGS) },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  resetMockDb("signed-in");
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------------
// Jobs: the list

describe("job list", () => {
  it("needs a session", async () => {
    resetMockDb("signed-out");
    expectProblem(await get("/api/v1/jobs"), 401, "auth.unauthenticated");
    expectProblem(await get(jobPath(MOCK_JOB_IDS.moveWaiting)), 401, "auth.unauthenticated");
    expectProblem(await post(`${jobPath(MOCK_JOB_IDS.moveWaiting)}/cancel`), 401, "auth.unauthenticated");
    expectProblem(await post(completePath(MOCK_JOB_IDS.moveWaiting, 1)), 401, "auth.unauthenticated");
  });

  it("lists the six seed jobs newest first", async () => {
    const page = await get<Page<JobSummary>>("/api/v1/jobs");
    expect(page.status).toBe(200);
    expect(page.body.revision).toBe(db.revision);
    expect(page.body.next_cursor ?? null).toBeNull();
    expect(page.body.items.map((j) => j.id)).toEqual([
      MOCK_JOB_IDS.importRunning,
      MOCK_JOB_IDS.applySucceeded,
      MOCK_JOB_IDS.moveQueued,
      MOCK_JOB_IDS.moveWaiting,
      MOCK_JOB_IDS.applyCancelled,
      MOCK_JOB_IDS.moveRolledBack,
    ]);
    const created = page.body.items.map((j) => Date.parse(j.created.at));
    expect(created).toEqual([...created].sort((a, b) => b - a));
  });

  it("derives the summary of the move job that waits for a person", async () => {
    const waiting = await summaryOf(MOCK_JOB_IDS.moveWaiting);
    expect(waiting).toMatchObject({
      kind: "ipam.move",
      title: "ipam.move.title",
      state: "waiting",
      group: MOCK_MOVE_GROUP,
      runner: 1,
      step_count: 6,
      steps_done: 1,
      current_step: 1,
      current_step_state: "waiting_for_manual",
      manual_steps: [1],
      cancel_requested: false,
      targets: [
        { kind: "host", id: MOCK_HOST_IDS.thermostat1 },
        { kind: "prefix", id: MOCK_MOVE_PREFIX },
      ],
      created: { by: { kind: "user", id: MOCK_USER_IDS.alex } },
    });
    expect(waiting.error).toBeUndefined();
    expect(waiting.finished).toBeUndefined();
    expect(waiting.revision).toBeGreaterThan(0);
  });

  it("derives the summaries of the other seed jobs", async () => {
    const queued = await summaryOf(MOCK_JOB_IDS.moveQueued);
    expect(queued).toMatchObject({
      state: "queued",
      group: MOCK_MOVE_GROUP,
      steps_done: 0,
      step_count: 6,
      current_step: 0,
      current_step_state: "pending",
      targets: [
        { kind: "host", id: MOCK_HOST_IDS.plugKitchen },
        { kind: "prefix", id: MOCK_MOVE_PREFIX },
      ],
    });
    expect(queued.runner).toBeUndefined();
    expect(queued.manual_steps).toBeUndefined();

    expect(await summaryOf(MOCK_JOB_IDS.importRunning)).toMatchObject({
      kind: "import.apply",
      title: "jobs.title.import_apply",
      state: "running",
      steps_done: 2,
      step_count: 3,
      current_step: 2,
      current_step_state: "running",
    });

    const applied = await summaryOf(MOCK_JOB_IDS.applySucceeded);
    expect(applied).toMatchObject({ kind: "ipam.apply", title: "jobs.title.ipam_apply", state: "succeeded", steps_done: 1, step_count: 1 });
    expect(applied.current_step).toBeUndefined();
    expect(applied.finished).toBeTypeOf("string");

    const rolledBack = await summaryOf(MOCK_JOB_IDS.moveRolledBack);
    expect(rolledBack).toMatchObject({
      state: "rolled_back",
      steps_done: 0,
      current_step: 0,
      current_step_state: "compensated",
      error: { code: "jobs.step.failed", detail: "No ARP or lease from 00:00:5e:00:53:2b within 5:00." },
    });
    expect(rolledBack.finished).toBeTypeOf("string");

    const cancelled = await summaryOf(MOCK_JOB_IDS.applyCancelled);
    expect(cancelled).toMatchObject({ kind: "ipam.apply", state: "cancelled", cancel_requested: true, error: { code: "jobs.cancelled" } });
  });

  it("filters by state and kind, as comma lists or repeated parameters", async () => {
    const ids = async (query: string) => (await get<Page<JobSummary>>(`/api/v1/jobs${query}`)).body.items.map((j) => j.id);
    expect(await ids("?state=running")).toEqual([MOCK_JOB_IDS.importRunning]);
    expect((await ids("?state=waiting,queued")).sort()).toEqual([MOCK_JOB_IDS.moveQueued, MOCK_JOB_IDS.moveWaiting].sort());
    expect((await ids("?state=waiting&state=queued")).sort()).toEqual([MOCK_JOB_IDS.moveQueued, MOCK_JOB_IDS.moveWaiting].sort());
    expect(await ids("?state=waiting,%20,")).toEqual([MOCK_JOB_IDS.moveWaiting]);
    expect(await ids("?state=failed")).toEqual([]);
    expect(await ids("?kind=import.apply")).toEqual([MOCK_JOB_IDS.importRunning]);
    expect(await ids("?kind=ipam.apply")).toEqual([MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.applyCancelled]);
    expect(await ids("?kind=ipam.apply,import.apply&state=cancelled")).toEqual([MOCK_JOB_IDS.applyCancelled]);
    expect(await ids("?kind=ipam.move&state=succeeded")).toEqual([]);
  });

  it("filters by target", async () => {
    const ids = async (target: string) =>
      (await get<Page<JobSummary>>(`/api/v1/jobs?target=${encodeURIComponent(target)}`)).body.items.map((j) => j.id);
    expect(await ids(`host/${MOCK_HOST_IDS.thermostat1}`)).toEqual([MOCK_JOB_IDS.moveWaiting]);
    expect(await ids(`host/${MOCK_HOST_IDS.nas}`)).toEqual([MOCK_JOB_IDS.applySucceeded]);
    expect(await ids(`prefix/${MOCK_HOST_IDS.nas}`)).toEqual([]);
  });

  it("pages with the cursor", async () => {
    const first = await get<Page<JobSummary>>("/api/v1/jobs?limit=4");
    expect(first.body.items).toHaveLength(4);
    expect(first.body.next_cursor).toBeTypeOf("string");
    const second = await get<Page<JobSummary>>(`/api/v1/jobs?limit=4&cursor=${first.body.next_cursor}`);
    expect(second.body.items).toHaveLength(2);
    expect(second.body.next_cursor ?? null).toBeNull();
    const all = (await get<Page<JobSummary>>("/api/v1/jobs")).body.items.map((j) => j.id);
    expect([...first.body.items, ...second.body.items].map((j) => j.id)).toEqual(all);
    expectProblem(await get("/api/v1/jobs?cursor=%25%25"), 400, "sys.invalid_cursor");
  });

  it("refuses malformed filters", async () => {
    const state = expectProblem(await get("/api/v1/jobs?state=sleeping"), 400, "jobs.query.invalid");
    expect(state.params).toEqual({ param: "state", value: "sleeping" });
    expect(expectProblem(await get("/api/v1/jobs?kind=Not%20A%20Kind"), 400, "jobs.query.invalid").params.param).toBe("kind");
    for (const target of ["host", "nothing/00000000-0000-0000-0000-000000000001", "host/not-a-uuid"]) {
      expect(expectProblem(await get(`/api/v1/jobs?target=${encodeURIComponent(target)}`), 400, "jobs.query.invalid").params.param).toBe("target");
    }
    const unknown = expectProblem(await get("/api/v1/jobs?colour=red"), 400, "sys.invalid_query");
    expect(unknown.params).toEqual({ parameter: "colour" });
    expectProblem(await get(`/api/v1/jobs?target=host/${MOCK_HOST_IDS.nas}&target=host/${MOCK_HOST_IDS.camDoor}`), 400, "sys.invalid_query");
    expectProblem(await get("/api/v1/jobs?at_least=soon"), 400, "sys.invalid_query");
    expect(expectProblem(await get("/api/v1/jobs?limit=0"), 400, "sys.invalid_query").params).toEqual({ parameter: "limit" });
    expectProblem(await get("/api/v1/jobs?limit=1001"), 400, "sys.invalid_query");
  });
});

// ---------------------------------------------------------------------------------
// Jobs: the detail

describe("job detail", () => {
  it("shows the steps, the preview and the transition log of a move job", async () => {
    const detail = await detailOf(MOCK_JOB_IDS.moveWaiting);
    expect(detail.revision).toBe(db.revision);
    const job = detail.job;
    expect(job.state).toBe("waiting");
    expect(job.spec).toMatchObject({ kind: "ipam.move", group: MOCK_MOVE_GROUP, group_limit: 2, timeout: 43200 });
    expect(job.steps.map((s) => s.kind)).toEqual([
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.l2",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    expect(job.steps.map((s) => s.state.state)).toEqual([
      "done",
      "waiting_for_manual",
      "pending",
      "pending",
      "pending",
      "pending",
    ]);
    expect(job.steps.map((s) => s.index)).toEqual([0, 1, 2, 3, 4, 5]);

    const waiting = job.steps[1]?.state;
    if (waiting?.state !== "waiting_for_manual") throw new Error("the DHCP step does not wait");
    // The arguments the server sends with every task, and no undo task: a rollback never waits for a person.
    expect(waiting.data.task).toEqual({
      instruction: "ipam.move.task.dhcp",
      args: MOVE_TASK_ARGS,
    });
    // The job started an hour ago and may run for 12 hours.
    const left = Date.parse(waiting.data.deadline ?? "") - Date.now();
    expect(left).toBeGreaterThan(10.9 * HOUR);
    expect(left).toBeLessThan(11.1 * HOUR);

    const preview = detail.preview;
    // A manual step is summarized by its task, an automatic one by its own message.
    expect(preview?.steps.map((s) => s.summary)).toEqual([
      "ipam.move.step.intent",
      "ipam.move.task.dhcp",
      "ipam.move.task.dns",
      "ipam.move.task.l2",
      "ipam.move.task.observe",
      "ipam.move.step.cleanup",
    ]);
    expect(preview?.steps[0]?.args).toEqual({ old_ip: "192.0.2.41", new_ip: "198.51.100.41", cidr: "198.51.100.0/24", vid: "30" });
    expect(preview?.steps[1]?.manual).toEqual(waiting.data.task);
    expect(preview?.steps[1]?.args).toEqual(waiting.data.task.args);
    expect(preview?.steps[3]?.manual).toEqual({ instruction: "ipam.move.task.l2", args: MOVE_TASK_ARGS });
    expect(preview?.steps[2]?.manual).toEqual({
      instruction: "ipam.move.task.dns",
      args: { ...MOVE_TASK_ARGS, name: "thermostat-1.example.test" },
    });
    expect(preview?.steps[4]?.manual).toEqual({
      instruction: "ipam.move.task.observe",
      args: { ...MOVE_TASK_ARGS, timeout_secs: "43200" },
    });
    expect(preview?.steps[0]?.manual).toBeUndefined();

    expect(detail.transitions.map((t) => t.seq)).toEqual(detail.transitions.map((_, i) => i));
    expect(detail.transitions.map((t) => `${t.event}:${t.action ?? t.step_state?.state ?? ""}`)).toEqual([
      "submitted:",
      "claimed:",
      "job:start",
      "step:running",
      "step:done",
      "step:running",
      "step:waiting_for_manual",
      "job:wait",
    ]);
    expect(detail.transitions[0]).toMatchObject({ state: "queued", by: { kind: "user", id: MOCK_USER_IDS.alex } });
    expect(detail.transitions[2]).toMatchObject({ from: "queued", state: "running", runner: 1 });
    expect(detail.transitions.at(-1)).toMatchObject({ from: "running", state: "waiting", by: { kind: "system", component: "jobs" } });
  });

  it("shows the rollback of the move job that failed on the layer 2 step, without a task to undo", async () => {
    const detail = await detailOf(MOCK_JOB_IDS.moveRolledBack);
    expect(detail.job.state).toBe("rolled_back");
    expect(detail.job.steps.map((s) => s.state.state)).toEqual([
      "compensated",
      "compensated",
      "compensated",
      "failed",
      "pending",
      "pending",
    ]);
    const failed = detail.job.steps[3]?.state;
    if (failed?.state !== "failed") throw new Error("the layer 2 step did not fail");
    expect(failed.data.error).toMatchObject({ code: "jobs.step.failed", detail: "No ARP or lease from 00:00:5e:00:53:2b within 5:00." });
    expect(detail.job.error?.code).toBe("jobs.step.failed");
    const log = detail.transitions.map((t) => `${t.event}:${t.action ?? t.step_state?.state ?? ""}`);
    expect(log).toContain("job:roll_back");
    expect(log.at(-1)).toBe("job:finish_rollback");
    // A person did the two manual tasks, with a note each; the rollback undid the steps by itself.
    const notes = detail.transitions.filter((t) => t.note).map((t) => [t.step, t.step_state?.state, t.by.kind]);
    expect(notes).toEqual([
      [1, "done", "user"],
      [2, "done", "user"],
    ]);
    expect(detail.transitions.filter((t) => t.step_state?.state === "compensated").map((t) => [t.step, t.by.kind])).toEqual([
      [2, "system"],
      [1, "system"],
      [0, "system"],
    ]);
    expect(detail.transitions.map((t) => t.seq)).toEqual(detail.transitions.map((_, i) => i));
  });

  it("has no preview for an inline job", async () => {
    const detail = await detailOf(MOCK_JOB_IDS.applySucceeded);
    expect(detail.preview ?? null).toBeNull();
    expect(detail.job.state).toBe("succeeded");
    expect(detail.transitions.at(-1)).toMatchObject({ event: "job", action: "complete", state: "succeeded" });
  });

  it("fails for an unknown or malformed identifier and for parameters it does not know", async () => {
    const missing = expectProblem(await get(jobPath("0190d1c2-0000-7000-8000-00000000ffff")), 404, "jobs.not_found");
    expect(missing.params).toEqual({ job: "0190d1c2-0000-7000-8000-00000000ffff" });
    const bad = expectProblem(await get(jobPath("dummy")), 400, "jobs.query.invalid");
    expect(bad.params).toEqual({ param: "id", value: "dummy" });
    expectProblem(await get(`${jobPath(MOCK_JOB_IDS.moveWaiting)}?limit=5`), 400, "sys.invalid_query");
    expectProblem(await get(`${jobPath(MOCK_JOB_IDS.moveWaiting)}?at_least=x`), 400, "sys.invalid_query");
    expect((await get(`${jobPath(MOCK_JOB_IDS.moveWaiting)}?at_least=${db.revision}`)).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------
// Jobs: manual steps

describe("completing manual steps", () => {
  it("moves the waiting DHCP step on to the DNS step and records the note and the audit record", async () => {
    const id = MOCK_JOB_IDS.moveWaiting;
    const revision = db.revision;
    const auditBefore = audit.records.length;
    const note = "Reserved 198.51.100.41 in the DHCP server.";
    const answer = await post<JobSummary>(completePath(id, 1), { note });
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({
      id,
      state: "waiting",
      steps_done: 2,
      current_step: 2,
      current_step_state: "waiting_for_manual",
      manual_steps: [2],
    });
    expect(answer.body.revision).toBeGreaterThan(revision);

    const detail = await detailOf(id);
    expect(taskOf(detail.job, 2)?.instruction).toBe("ipam.move.task.dns");
    const noted = detail.transitions.filter((t) => t.note);
    expect(noted).toHaveLength(1);
    expect(noted[0]).toMatchObject({ event: "step", step: 1, note, step_state: { state: "done" }, by: { kind: "user", id: MOCK_USER_IDS.alex } });
    // The person's rows come first; the engine goes on with the next step.
    const tail = detail.transitions.slice(-5).map((t) => `${t.event}:${t.action ?? t.step_state?.state}`);
    expect(tail).toEqual(["step:done", "job:resume", "step:running", "step:waiting_for_manual", "job:wait"]);

    expect(audit.records).toHaveLength(auditBefore + 1);
    const record = audit.records.at(-1);
    expect(record?.draft).toMatchObject({
      action: "jobs.step.complete",
      objects: [{ kind: "job", id }],
      outcome: { kind: "success" },
      details: { context: { step: "1", note } },
    });
    expect(record?.principal).toMatchObject({ kind: "user", id: MOCK_USER_IDS.alex });
    const journal = db.journal.filter((e) => e.topic === "jobs");
    expect(journal.at(-1)?.data.objects).toEqual([{ kind: "job", id }]);
    expect(db.journal.filter((e) => e.topic === "audit").at(-1)?.data.audit).toEqual([record?.seq]);
  });

  it("walks the whole move job to succeeded and starts the queued job of the group", async () => {
    const id = MOCK_JOB_IDS.moveWaiting;
    const queued = MOCK_JOB_IDS.moveQueued;

    // The queued job waits while the first one has not finished.
    expect((await post<JobSummary>(completePath(id, 1), { note: "dhcp" })).body.current_step).toBe(2);
    expect((await summaryOf(queued)).state).toBe("queued");
    const dns = await post<JobSummary>(completePath(id, 2), { note: "dns" });
    expect(dns.body).toMatchObject({ current_step: 3, manual_steps: [3] });
    expect(taskOf((await detailOf(id)).job, 3)?.instruction).toBe("ipam.move.task.l2");
    expect((await post<JobSummary>(completePath(id, 3))).body).toMatchObject({ current_step: 4, manual_steps: [4] });

    // The observation step gets a deadline of the job timeout from now.
    const observe = (await detailOf(id)).job.steps[4]?.state;
    if (observe?.state !== "waiting_for_manual") throw new Error("the observation step does not wait");
    expect(observe.data.task).toMatchObject({
      instruction: "ipam.move.task.observe",
      args: { host: "thermostat-1", new_ip: "198.51.100.41", timeout_secs: "43200" },
    });
    const left = Date.parse(observe.data.deadline ?? "") - Date.now();
    expect(left).toBeGreaterThan(11.9 * HOUR);
    expect(left).toBeLessThanOrEqual(12 * HOUR);
    expect((await summaryOf(queued)).state).toBe("queued");

    // The automatic cleanup step runs at once and the job is done.
    const last = await post<JobSummary>(completePath(id, 4), { note: "seen" });
    expect(last.status).toBe(200);
    expect(last.body).toMatchObject({ state: "succeeded", steps_done: 6, step_count: 6 });
    expect(last.body.finished).toBeTypeOf("string");
    expect(last.body.current_step).toBeUndefined();
    expect(last.body.manual_steps).toBeUndefined();
    const finished = await detailOf(id);
    expect(finished.job.steps.every((s) => s.state.state === "done")).toBe(true);
    expect(finished.transitions.at(-1)).toMatchObject({ event: "job", action: "complete", from: "running", state: "succeeded" });
    expect(finished.transitions.filter((t) => t.note).map((t) => t.note)).toEqual(["dhcp", "dns", "seen"]);

    // The slot is free: the queued job started, its intent is done and its first task waits.
    const started = await detailOf(queued);
    expect(started.job.state).toBe("waiting");
    expect(started.job.runner).toBe(1);
    expect(started.job.steps.map((s) => s.state.state).slice(0, 3)).toEqual(["done", "waiting_for_manual", "pending"]);
    expect(taskOf(started.job, 1)).toMatchObject({ instruction: "ipam.move.task.dhcp", args: { host: "plug-kitchen", new_ip: "198.51.100.42" } });
    expect(started.transitions.map((t) => t.event).slice(0, 3)).toEqual(["submitted", "claimed", "job"]);
    expect(audit.records.filter((r) => r.draft.action === "jobs.step.complete")).toHaveLength(2 + 4);
  });

  it("refuses a step that does not wait for a person", async () => {
    const id = MOCK_JOB_IDS.moveWaiting;
    for (const index of [0, 2, 5]) {
      const problem = expectProblem(await post(completePath(id, index)), 409, "jobs.invalid_transition");
      expect(problem.params).toEqual({ from: "Waiting", action: "complete_manual" });
    }
    expect(expectProblem(await post(completePath(MOCK_JOB_IDS.moveQueued, 1)), 409, "jobs.invalid_transition").params.from).toBe("Queued");
    expect(expectProblem(await post(completePath(MOCK_JOB_IDS.applySucceeded, 0)), 409, "jobs.invalid_transition").params.from).toBe("Succeeded");
    // Completing twice conflicts as well.
    expect((await post(completePath(id, 1))).status).toBe(200);
    expectProblem(await post(completePath(id, 1)), 409, "jobs.invalid_transition");
    // Nothing of that wrote an audit record for the refused calls.
    expect(audit.records.filter((r) => r.draft.action === "jobs.step.complete").map((r) => r.draft.details?.context?.step)).toContain("1");
  });

  it("fails for an unknown job or step, a bad index, a long note and a malformed body", async () => {
    const id = MOCK_JOB_IDS.moveWaiting;
    expectProblem(await post(completePath("0190d1c2-0000-7000-8000-00000000ffff", 1)), 404, "jobs.not_found");
    const step = expectProblem(await post(completePath(id, 9)), 404, "jobs.step.not_found");
    expect(step.params).toEqual({ job: id, step: "9" });
    for (const index of ["x", "-1", "65536", "1.5"]) {
      const problem = expectProblem(await post(`/api/v1/jobs/${id}/steps/${index}/complete`), 400, "jobs.query.invalid");
      expect(problem.params).toEqual({ param: "index", value: index });
    }
    expectProblem(await post(completePath("dummy", 1)), 400, "jobs.query.invalid");

    expectProblem(await post(completePath(id, 1), { note: "n".repeat(MAX_NOTE_BYTES + 1) }), 400, "jobs.note.too_long");
    // A multi-byte note counts bytes, not characters.
    expectProblem(await post(completePath(id, 1), { note: "å".repeat(MAX_NOTE_BYTES / 2 + 1) }), 400, "jobs.note.too_long");
    for (const body of ["not json", '{"note":5}', '{"note":"x","extra":1}', "[]", "null"]) {
      expectProblem(await callRaw("POST", completePath(id, 1), body), 400, "sys.invalid_request");
    }
    // Nothing of that changed the job.
    expect(stateOf((await detailOf(id)).job, 1)).toBe("waiting_for_manual");

    // A note of exactly the limit is accepted; an empty body, `{}` and a null note are too.
    expect((await post(completePath(id, 1), { note: "n".repeat(MAX_NOTE_BYTES) })).status).toBe(200);
    resetMockDb("signed-in");
    for (const body of [undefined, {}, { note: null }]) {
      resetMockDb("signed-in");
      const answer = await post<JobSummary>(completePath(id, 1), body);
      expect(answer.status).toBe(200);
      expect((await detailOf(id)).transitions.filter((t) => t.note)).toEqual([]);
      expect(audit.records.at(-1)?.draft.details?.context).toEqual({ step: "1" });
    }
  });

  it("is for operators and administrators; a viewer only reads", async () => {
    const alex = db.users.find((u) => u.id === MOCK_USER_IDS.alex);
    if (!alex) throw new Error("no alex");
    alex.roles = ["viewer"];
    const id = MOCK_JOB_IDS.moveWaiting;
    expectProblem(await post(completePath(id, 1)), 403, "auth.forbidden");
    expectProblem(await post(`${jobPath(id)}/cancel`), 403, "auth.forbidden");
    expect((await get(jobPath(id))).status).toBe(200);
    expect((await get("/api/v1/jobs")).status).toBe(200);
    alex.roles = ["operator"];
    expect((await post(completePath(id, 1))).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------
// Jobs: cancel

describe("cancelling jobs", () => {
  it("cancels a queued job at once", async () => {
    const id = MOCK_JOB_IDS.moveQueued;
    const auditBefore = audit.records.length;
    const answer = await post<JobSummary>(`${jobPath(id)}/cancel`);
    expect(answer.status).toBe(202);
    expect(answer.body).toMatchObject({ id, state: "cancelled", cancel_requested: true, error: { code: "jobs.cancelled" } });
    expect(answer.body.finished).toBeTypeOf("string");
    const detail = await detailOf(id);
    expect(detail.job.cancel_requested).toMatchObject({ by: { kind: "user", id: MOCK_USER_IDS.alex } });
    expect(detail.transitions.at(-1)).toMatchObject({ event: "job", action: "cancel", from: "queued", state: "cancelled" });
    expect(audit.records).toHaveLength(auditBefore + 1);
    expect(audit.records.at(-1)?.draft).toMatchObject({ action: "jobs.job.cancel", objects: [{ kind: "job", id }] });
    expect(db.journal.filter((e) => e.topic === "jobs").at(-1)?.data.objects).toEqual([{ kind: "job", id }]);
  });

  it("refuses to cancel a job that is finished or rolling back", async () => {
    const id = MOCK_JOB_IDS.moveQueued;
    expect((await post(`${jobPath(id)}/cancel`)).status).toBe(202);
    const again = expectProblem(await post(`${jobPath(id)}/cancel`), 409, "jobs.invalid_transition");
    expect(again.params).toEqual({ from: "Cancelled", action: "cancel" });
    for (const done of [MOCK_JOB_IDS.applySucceeded, MOCK_JOB_IDS.moveRolledBack, MOCK_JOB_IDS.applyCancelled]) {
      expectProblem(await post(`${jobPath(done)}/cancel`), 409, "jobs.invalid_transition");
    }
    // The cancelled waiting move has no task to undo, so it is cancelled for good at once.
    expect((await post(`${jobPath(MOCK_JOB_IDS.moveWaiting)}/cancel`)).status).toBe(202);
    expect(expectProblem(await post(`${jobPath(MOCK_JOB_IDS.moveWaiting)}/cancel`), 409, "jobs.invalid_transition").params.from).toBe("Cancelled");
    // A job with an undo task stays rolling back until a person has undone it.
    const rolling = createJob(undoJob());
    expect((await post(`${jobPath(rolling)}/cancel`)).status).toBe(202);
    expect(expectProblem(await post(`${jobPath(rolling)}/cancel`), 409, "jobs.invalid_transition").params.from).toBe("RollingBack");
    expectProblem(await post(`${jobPath("0190d1c2-0000-7000-8000-00000000ffff")}/cancel`), 404, "jobs.not_found");
    expectProblem(await post(`${jobPath("dummy")}/cancel`), 400, "jobs.query.invalid");
  });

  it("rolls a waiting move back at once: its manual steps have no undo task, and the queued job starts", async () => {
    const id = MOCK_JOB_IDS.moveWaiting;
    const answer = await post<JobSummary>(`${jobPath(id)}/cancel`);
    expect(answer.status).toBe(202);
    expect(answer.body).toMatchObject({
      state: "cancelled",
      cancel_requested: true,
      error: { code: "jobs.cancelled" },
      steps_done: 0,
      // The first step that is neither done nor skipped: the intent was compensated.
      current_step: 0,
      current_step_state: "compensated",
    });
    expect(answer.body.manual_steps).toBeUndefined();
    expect(answer.body.finished).toBeTypeOf("string");

    const detail = await detailOf(id);
    expect(detail.job.steps.map((s) => s.state.state)).toEqual([
      "compensated",
      "compensated",
      "pending",
      "pending",
      "pending",
      "pending",
    ]);
    expect(detail.transitions.map((t) => `${t.event}:${t.action ?? t.step_state?.state ?? ""}`).slice(8)).toEqual([
      "cancel_requested:",
      "step:failed",
      "job:cancel",
      "step:compensating",
      "step:compensated",
      "step:compensating",
      "step:compensated",
      "job:finish_cancel",
    ]);
    // The slot goes to the queued job of the group.
    expect((await summaryOf(MOCK_JOB_IDS.moveQueued)).state).toBe("waiting");
    expect(audit.records.map((r) => r.draft.action).at(-1)).toBe("jobs.job.cancel_request");
  });

  it("rolls a waiting job back: the task becomes an undo task and the job ends cancelled when it is done", async () => {
    const id = createJob(undoJob());
    const answer = await post<JobSummary>(`${jobPath(id)}/cancel`);
    expect(answer.status).toBe(202);
    expect(answer.body).toMatchObject({
      state: "rolling_back",
      cancel_requested: true,
      error: { code: "jobs.cancelled" },
      manual_steps: [1],
      // The first step that is neither done nor skipped: the intent was compensated.
      current_step: 0,
      current_step_state: "compensated",
    });
    expect(answer.body.finished).toBeUndefined();

    const rolling = await detailOf(id);
    expect(rolling.job.steps.map((s) => s.state.state)).toEqual(["compensated", "waiting_for_manual", "pending"]);
    // The undo task: the undo message with the arguments of the task it undoes.
    expect(taskOf(rolling.job, 1)).toEqual({
      instruction: "jobs.task.dhcp_release",
      args: { host: "nas", mac: "00:00:5e:00:53:0b", ip: "198.51.100.44", prefix: "198.51.100.0/24" },
    });
    expect(rolling.transitions.map((t) => `${t.event}:${t.action ?? t.step_state?.state ?? ""}`).slice(-6)).toEqual([
      "cancel_requested:",
      "step:failed",
      "job:cancel",
      "step:waiting_for_manual",
      "step:compensating",
      "step:compensated",
    ]);

    // A person undoes it; the rollback finishes.
    const done = await post<JobSummary>(completePath(id, 1), { note: "Released the reservation." });
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ state: "cancelled", steps_done: 0, error: { code: "jobs.cancelled" } });
    expect(done.body.manual_steps).toBeUndefined();
    const finished = await detailOf(id);
    expect(finished.job.steps.map((s) => s.state.state).slice(0, 2)).toEqual(["compensated", "compensated"]);
    expect(finished.transitions.at(-1)).toMatchObject({ action: "finish_cancel", from: "rolling_back", state: "cancelled" });
    expect(audit.records.map((r) => r.draft.action).slice(-2)).toEqual(["jobs.job.cancel_request", "jobs.step.complete"]);
  });

  it("rolls a running import back at once", async () => {
    const answer = await post<JobSummary>(`${jobPath(MOCK_JOB_IDS.importRunning)}/cancel`);
    expect(answer.status).toBe(202);
    expect(answer.body).toMatchObject({ state: "cancelled", cancel_requested: true, error: { code: "jobs.cancelled" }, steps_done: 0 });
    const detail = await detailOf(MOCK_JOB_IDS.importRunning);
    expect(detail.job.steps.map((s) => s.state.state)).toEqual(["compensated", "compensated", "compensated"]);
  });
});

// ---------------------------------------------------------------------------------
// Jobs: createJob and the group rule

describe("createJob", () => {
  it("starts the job, finishes the automatic steps and waits at the first manual one", async () => {
    const before = db.revision;
    const id = createJob(plainJob());
    expect(db.revision).toBe(before + 1);
    expect(db.journal.at(-1)).toMatchObject({ topic: "jobs", data: { objects: [{ kind: "job", id }] } });

    const detail = await detailOf(id);
    expect(detail.job.state).toBe("waiting");
    expect(detail.job.created.by).toMatchObject({ kind: "user", id: MOCK_USER_IDS.alex });
    expect(detail.job.steps.map((s) => s.state.state)).toEqual(["done", "waiting_for_manual"]);
    expect(taskOf(detail.job, 1)).toEqual({ instruction: "ipam.move.task.observe", args: OBSERVE_ARGS });
    expect(detail.preview?.steps.map((s) => s.summary)).toEqual(["ipam.move.step.intent", "ipam.move.task.observe"]);
    expect(detail.transitions.map((t) => t.seq)).toEqual(detail.transitions.map((_, i) => i));
    expect((await summaryOf(id)).state).toBe("waiting");
    // It is the newest job.
    expect((await get<Page<JobSummary>>("/api/v1/jobs")).body.items[0]?.id).toBe(id);
    // A person finishes it.
    expect((await post<JobSummary>(completePath(id, 1))).body.state).toBe("succeeded");
  });

  it("marks the first steps done when the caller executed them", async () => {
    const input = plainJob({
      steps: [
        { kind: "ipam.move.intent", automatic: false },
        { kind: "ipam.move.observe", automatic: false, manual: manualTask("ipam.move.observe", OBSERVE_ARGS) },
      ],
    });
    expect(() => createJob(input)).toThrow(/neither automatic nor a manual task/);
    const id = createJob(input, { startedSteps: 1 });
    const job = (await detailOf(id)).job;
    expect(job.steps.map((s) => s.state.state)).toEqual(["done", "waiting_for_manual"]);
    expect(job.steps[0]?.attempts).toBe(1);
  });

  it("queues a job of a full group and starts it when a slot frees up", async () => {
    const group = { group: "move-test", groupLimit: 1 };
    const first = createJob(plainJob(group));
    const second = createJob(plainJob(group));
    const third = createJob(plainJob(group));
    const states = async () => [(await summaryOf(first)).state, (await summaryOf(second)).state, (await summaryOf(third)).state];
    expect(await states()).toEqual(["waiting", "queued", "queued"]);
    expect((await detailOf(second)).job.spec).toMatchObject({ group: "move-test", group_limit: 1 });
    expect((await summaryOf(second)).runner).toBeUndefined();

    // Finishing the first job starts the oldest queued one only (the limit is one).
    expect((await post<JobSummary>(completePath(first, 1))).body.state).toBe("succeeded");
    expect(await states()).toEqual(["succeeded", "waiting", "queued"]);
    // Cancelling the running one frees the slot as well; its manual step has no undo task.
    expect((await post<JobSummary>(`${jobPath(second)}/cancel`)).body.state).toBe("cancelled");
    expect(await states()).toEqual(["succeeded", "cancelled", "waiting"]);
  });

  it("lets a group with room start the new job, but keeps the order of the queue", async () => {
    // The seed group has a limit of two and one job that holds a slot; its queued job starts
    // first, then the new one finds the group full.
    const id = createJob(
      moveJobInput({
        host: { kind: "host", id: MOCK_HOST_IDS.nas },
        name: "nas",
        fqdn: "nas.example.test",
        mac: "00:00:5e:00:53:10",
        ip: "198.51.100.44",
        oldIp: "192.0.2.11",
        group: MOCK_MOVE_GROUP,
        groupLimit: 2,
      }),
    );
    expect((await summaryOf(MOCK_JOB_IDS.moveQueued)).state).toBe("waiting");
    expect((await summaryOf(id)).state).toBe("queued");
  });

  it("builds the move job input like the server: kinds, order, task keys and arguments", () => {
    const move = {
      host: { kind: "host" as const, id: MOCK_HOST_IDS.nas },
      name: "nas",
      fqdn: "nas.example.test",
      mac: "00:00:5e:00:53:0b",
      ip: "198.51.100.44",
      oldIp: "192.0.2.11",
    };
    const kinds = (input: MockJobInput) => input.steps.map((s) => s.kind);

    // A reserved host (the default) gets a DHCP step, a name a DNS step.
    const reserved = moveJobInput(move);
    expect(reserved).toMatchObject({ kind: "ipam.move", title: "ipam.move.title" });
    expect(kinds(reserved)).toEqual([
      "ipam.move.intent",
      "ipam.move.dhcp",
      "ipam.move.dns",
      "ipam.move.l2",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    // A static host gets a device step, after the DNS step; a host without a name gets no DNS step.
    expect(kinds(moveJobInput({ ...move, mode: "static" }))).toEqual([
      "ipam.move.intent",
      "ipam.move.dns",
      "ipam.move.device",
      "ipam.move.l2",
      "ipam.move.observe",
      "ipam.move.cleanup",
    ]);
    const { fqdn: _name, ...unnamed } = move;
    expect(kinds(moveJobInput({ ...unnamed, mode: "dynamic" }))).toEqual(["ipam.move.intent", "ipam.move.l2", "ipam.move.observe", "ipam.move.cleanup"]);

    // Every task carries the same arguments; DNS adds the name, the observation the timeout.
    const tasks = reserved.steps.flatMap((step) => (step.manual ? [step.manual] : []));
    expect(tasks.map((t) => t.instruction)).toEqual([
      "ipam.move.task.dhcp",
      "ipam.move.task.dns",
      "ipam.move.task.l2",
      "ipam.move.task.observe",
    ]);
    for (const task of tasks) {
      expect(task.undo).toBeUndefined();
      expect(Object.keys(task.args ?? {})).toEqual(
        expect.arrayContaining(["prefix", "cidr", "vrf", "old_ip", "new_ip", "address", "new_address", "vlan", "vid", "host", "mac"]),
      );
      expect(task.args).toMatchObject({ cidr: "198.51.100.0/24", old_ip: "192.0.2.11", new_ip: "198.51.100.44", host: "nas", vid: "30" });
    }
    expect(tasks[1]?.args).toMatchObject({ name: "nas.example.test" });
    expect(tasks[3]?.args).toMatchObject({ timeout_secs: "43200" });
    // The automatic steps are summarized by their own messages, with the addresses and the network.
    expect(reserved.steps[0]).toMatchObject({
      automatic: true,
      summary: "ipam.move.step.intent",
      args: { old_ip: "192.0.2.11", new_ip: "198.51.100.44", cidr: "198.51.100.0/24", vid: "30" },
    });
    expect(reserved.steps.at(-1)).toMatchObject({ automatic: true, summary: "ipam.move.step.cleanup" });
    expect(() => manualTask("ipam.move.cleanup", {})).toThrow();
  });

  it("records an inline job as a succeeded one-step job", async () => {
    const before = db.revision;
    const id = recordInlineJob({ kind: "ipam.apply", title: "jobs.title.ipam_apply", targets: [{ kind: "host", id: MOCK_HOST_IDS.nas }] });
    expect(db.revision).toBe(before + 1);
    const detail = await detailOf(id);
    expect(detail.job).toMatchObject({ state: "succeeded", spec: { kind: "ipam.apply" } });
    expect(detail.job.steps).toHaveLength(1);
    expect(detail.job.revision).toBe(db.revision);
    expect(detail.preview ?? null).toBeNull();
    expect(detail.transitions.map((t) => t.event)).toEqual(["submitted", "claimed", "job", "step", "step", "job"]);
  });

  it("starts empty in the setup scenarios and seeds again after a reset", async () => {
    resetMockDb("setup");
    expect(jobStore.jobs).toEqual([]);
    expect(audit.records).toEqual([]);
    resetMockDb("signed-out");
    expect(jobStore.jobs).toHaveLength(6);
    expect(db.revision).toBe(INITIAL_REVISION);
  });
});

// ---------------------------------------------------------------------------------
// Jobs: the ticker

describe("job ticker", () => {
  it("advances the running import one step at a time and starts the next import", async () => {
    const import1 = recordOf(MOCK_JOB_IDS.importRunning);
    const before = db.revision;
    const event = advanceMockJobs();
    expect(db.revision).toBe(before + 1);
    expect(event).toMatchObject({ topic: "jobs", data: { objects: [{ kind: "job", id: MOCK_JOB_IDS.importRunning }] } });
    expect(import1.job.state).toBe("succeeded");
    expect(import1.job.steps.map((s) => s.state.state)).toEqual(["done", "done", "done"]);

    advanceMockJobs();
    const running = jobStore.jobs.filter((r) => r.job.spec.kind === "import.apply" && r.job.state === "running");
    expect(running).toHaveLength(1);
    const next = running[0];
    expect(next?.job.steps.map((s) => s.state.state)).toEqual(["running", "pending", "pending"]);
    advanceMockJobs();
    expect(next?.job.steps.map((s) => s.state.state)).toEqual(["done", "running", "pending"]);
    advanceMockJobs();
    advanceMockJobs();
    expect(next?.job.state).toBe("succeeded");
    expect((await summaryOf(next?.job.id ?? "")).steps_done).toBe(3);
  });

  it("rolls a move back at once when its timeout passed, and starts the queued job", async () => {
    const rec = recordOf(MOCK_JOB_IDS.moveWaiting);
    // It started 13 hours ago and may run for 12 hours.
    const started = new Date(Date.now() - 13 * HOUR).toISOString();
    rec.job.started = started;
    const first = rec.job.steps[0];
    if (first) first.started = started;

    const before = db.revision;
    advanceMockJobs();
    expect(db.revision).toBeGreaterThan(before);
    expect(db.journal.filter((e) => e.topic === "jobs").at(-1)?.data.objects.map((o) => o.id)).toContain(MOCK_JOB_IDS.moveWaiting);
    // No step has an undo task: nothing waits for a person.
    expect(rec.job.state).toBe("rolled_back");
    expect(rec.job.error).toMatchObject({ code: "jobs.timeout" });
    expect(rec.job.steps.map((s) => s.state.state).slice(0, 3)).toEqual(["compensated", "compensated", "pending"]);
    expect(rec.transitions.at(-1)).toMatchObject({ action: "finish_rollback", state: "rolled_back" });
    expect(audit.records.at(-1)).toMatchObject({
      principal: { kind: "system", component: "jobs" },
      draft: { action: "jobs.job.roll_back", outcome: { kind: "failed", code: "jobs.timeout" } },
    });
    // The slot is free again.
    expect((await summaryOf(MOCK_JOB_IDS.moveQueued)).state).toBe("waiting");
  });

  it("rolls back a job whose timeout passed: undo tasks first, then rolled back", async () => {
    const id = createJob(undoJob({ timeoutSecs: 600 }));
    const rec = recordOf(id);
    const started = new Date(Date.now() - 20 * 60_000).toISOString();
    rec.job.started = started;
    const first = rec.job.steps[0];
    if (first) first.started = started;

    advanceMockJobs();
    expect(rec.job.state).toBe("rolling_back");
    expect(rec.job.error).toMatchObject({ code: "jobs.timeout" });
    expect(rec.job.steps.map((s) => s.state.state)).toEqual(["compensated", "waiting_for_manual", "pending"]);
    expect(taskOf(rec.job, 1)?.instruction).toBe("jobs.task.dhcp_release");

    const answer = await post<JobSummary>(completePath(id, 1), { note: "Released." });
    expect(answer.body).toMatchObject({ state: "rolled_back", error: { code: "jobs.timeout" } });
    expect(answer.body.finished).toBeTypeOf("string");
    expect(rec.transitions.at(-1)).toMatchObject({ action: "finish_rollback", state: "rolled_back" });
  });

  it("rolls back a job whose waiting step passed its own deadline", () => {
    const rec = recordOf(MOCK_JOB_IDS.moveWaiting);
    const step = rec.job.steps[1];
    if (step?.state.state !== "waiting_for_manual") throw new Error("the DHCP step does not wait");
    step.state = { state: "waiting_for_manual", data: { ...step.state.data, deadline: new Date(Date.now() - 1000).toISOString() } };
    advanceMockJobs();
    expect(rec.job.state).toBe("rolled_back");
    expect(rec.job.error).toMatchObject({ code: "jobs.step.deadline_passed", params: { step: "1" } });
  });

  it("rolls back at once when no step has an undo task, and starts the queued job", () => {
    const id = createJob(plainJob({ timeoutSecs: 60 }));
    const rec = recordOf(id);
    const started = new Date(Date.now() - 120_000).toISOString();
    rec.job.started = started;
    const first = rec.job.steps[0];
    if (first) first.started = started;
    advanceMockJobs();
    expect(rec.job.state).toBe("rolled_back");
    expect(rec.job.error?.code).toBe("jobs.timeout");
    expect(rec.job.finished).toBeTypeOf("string");
    expect(rec.job.steps.map((s) => s.state.state)).toEqual(["compensated", "compensated"]);
  });

  it("notices the deadline of the observation step after the clock moved on", () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const id = createJob(plainJob({ timeoutSecs: 600 }));
    const rec = recordOf(id);
    advanceMockJobs();
    expect(rec.job.state).toBe("waiting");
    vi.setSystemTime(Date.now() + 11 * 60_000);
    advanceMockJobs();
    expect(rec.job.state).toBe("rolled_back");
    expect(rec.job.error?.code).toBe("jobs.timeout");
  });

  it("keeps the list short by dropping the oldest finished jobs", () => {
    for (let i = 0; i < 40; i += 1) createJob(plainJob({ steps: [{ kind: "ipam.move.intent", automatic: true }] }));
    expect(jobStore.jobs.length).toBe(46);
    const event = advanceMockJobs();
    expect(jobStore.jobs.length).toBeLessThanOrEqual(KEEP_JOBS);
    expect(event.data.deleted.length).toBeGreaterThan(0);
    // The oldest finished seed job fell off; jobs that are not finished stay.
    expect(findJob(MOCK_JOB_IDS.moveRolledBack)).toBeUndefined();
    expect(findJob(MOCK_JOB_IDS.moveWaiting)).toBeDefined();
    expect(findJob(MOCK_JOB_IDS.moveQueued)).toBeDefined();
    for (const gone of event.data.deleted) expect(findJob(gone.id)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------------
// Audit

describe("audit log", () => {
  it("needs a session and is readable by every role", async () => {
    resetMockDb("signed-out");
    expectProblem(await get("/api/v1/audit"), 401, "auth.unauthenticated");
    expectProblem(await get("/api/v1/audit/1"), 401, "auth.unauthenticated");
    expectProblem(await get("/api/v1/audit/verify"), 401, "auth.unauthenticated");
    resetMockDb("signed-in");
    const alex = db.users.find((u) => u.id === MOCK_USER_IDS.alex);
    if (alex) alex.roles = ["viewer"];
    expect((await get("/api/v1/audit")).status).toBe(200);
    expect((await get("/api/v1/audit/verify")).status).toBe(200);
  });

  it("seeds about forty linked records over the last seven days", () => {
    const records = audit.records;
    expect(records.length).toBeGreaterThanOrEqual(35);
    expect(records.length).toBeLessThanOrEqual(45);
    expect(records.map((r) => r.seq)).toEqual(records.map((_, i) => i + 1));
    expect(records[0]?.prev).toBe("0".repeat(64));
    records.forEach((record, i) => {
      if (i > 0) expect(record.prev).toBe(records[i - 1]?.hash);
      expect(record.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(record.hash).toBe(recordDigest(record));
    });
    const times = records.map((r) => Date.parse(r.at));
    expect(times).toEqual([...times].sort((a, b) => a - b));
    const age = Date.now() - (times[0] ?? 0);
    expect(age).toBeGreaterThan(6 * 24 * HOUR);
    expect(age).toBeLessThan(7 * 24 * HOUR);
    const revisions = records.map((r) => r.revision);
    expect(new Set(revisions).size).toBe(records.length);
    expect(Math.max(...revisions)).toBeLessThanOrEqual(db.revision);
  });

  it("seeds the records the audit view needs", () => {
    const by = (action: string) => audit.records.filter((r) => r.draft.action === action);
    expect(by("auth.login.success")[0]).toMatchObject({
      principal: { kind: "user", id: MOCK_USER_IDS.alex, strength: "passkey" },
      draft: { details: { context: { method: "passkey" } } },
    });
    const denied = by("auth.login.failure");
    expect(denied).toHaveLength(2);
    for (const record of denied) {
      expect(record.draft.outcome).toEqual({ kind: "denied" });
      expect(record.draft.details?.context).toEqual({ user: "admin" });
    }
    expect(by("settings.security.update")[0]?.draft.details?.changes).toEqual([{ field: "TGL-02", old: "on", new: "off" }]);
    expect(by("users.user.create").map((r) => r.draft.objects?.[0])).toContainEqual({ kind: "user", id: MOCK_USER_IDS.sam });
    expect(by("ipam.prefix.create").some((r) => r.draft.details?.changes?.some((c) => c.new === "192.0.2.0/24"))).toBe(true);
    expect(by("ipam.host.update")[0]?.draft.details?.changes).toEqual([{ field: "mode", old: "static", new: "reserved" }]);
    expect(by("ipam.address.delete")[0]?.draft.details?.changes).toEqual([{ field: "ip", old: "192.0.2.35", new: null }]);
    expect(by("jobs.step.complete").every((r) => !!r.draft.details?.context?.note)).toBe(true);
    expect(audit.records.filter((r) => r.draft.outcome.kind === "failed").map((r) => r.draft.outcome)).toContainEqual({
      kind: "failed",
      code: "ipam.prefix.overlap",
    });
    expect(by("ipam.prefix.alarm").length).toBeGreaterThan(0);
    for (const alarm of by("ipam.prefix.alarm")) expect(alarm.principal).toEqual({ kind: "system", component: "ipam" });
    // The ids the records name are the ones of the seed jobs.
    expect(AUDIT_SEED_IDS.jobRolledBack).toBe(MOCK_JOB_IDS.moveRolledBack);
    expect(AUDIT_SEED_IDS.jobCancelled).toBe(MOCK_JOB_IDS.applyCancelled);
    expect(AUDIT_SEED_IDS.hostNas).toBe(MOCK_HOST_IDS.nas);
    expect(AUDIT_SEED_IDS.hostThermostat).toBe(MOCK_HOST_IDS.thermostat1);
    expect(AUDIT_SEED_IDS.hostCamDoor).toBe(MOCK_HOST_IDS.camDoor);
  });

  it("lists newest first by default and oldest first with order=asc", async () => {
    const desc = await get<Page<AuditRecord>>("/api/v1/audit?limit=1000");
    expect(desc.status).toBe(200);
    expect(desc.body.revision).toBe(db.revision);
    expect(desc.body.items.map((r) => r.seq)).toEqual(audit.records.map((r) => r.seq).reverse());
    const asc = await get<Page<AuditRecord>>("/api/v1/audit?order=asc&limit=1000");
    expect(asc.body.items.map((r) => r.seq)).toEqual(audit.records.map((r) => r.seq));
    expect((await get<Page<AuditRecord>>("/api/v1/audit?order=desc")).body.items[0]?.seq).toBe(audit.records.length);
  });

  it("pages with the cursor in both directions", async () => {
    for (const order of ["desc", "asc"]) {
      const seen: number[] = [];
      let cursor = "";
      for (let guard = 0; guard < 20; guard += 1) {
        const page = await get<Page<AuditRecord>>(`/api/v1/audit?order=${order}&limit=7${cursor}`);
        seen.push(...page.body.items.map((r) => r.seq));
        if (!page.body.next_cursor) break;
        cursor = `&cursor=${page.body.next_cursor}`;
      }
      const expected = audit.records.map((r) => r.seq);
      expect(seen).toEqual(order === "asc" ? expected : expected.reverse());
    }
  });

  it("filters by principal, action, object, outcome and time", async () => {
    const seqs = async (query: string) => (await get<Page<AuditRecord>>(`/api/v1/audit?order=asc&limit=1000&${query}`)).body.items.map((r) => r.seq);
    const expected = (test: (r: AuditRecord) => boolean) => audit.records.filter(test).map((r) => r.seq);

    expect(await seqs("principal=system:ipam")).toEqual(expected((r) => r.principal.kind === "system" && r.principal.component === "ipam"));
    expect((await seqs("principal=system:ipam")).length).toBeGreaterThan(0);
    expect(await seqs(`principal=user:${MOCK_USER_IDS.sam}`)).toEqual(expected((r) => r.principal.kind === "user" && r.principal.id === MOCK_USER_IDS.sam));
    expect(await seqs("principal=user:nobody")).toEqual([]);

    expect(await seqs("action=ipam.prefix.create")).toEqual(expected((r) => r.draft.action === "ipam.prefix.create"));
    expect(await seqs("action=ipam.")).toEqual(expected((r) => r.draft.action.startsWith("ipam.")));
    expect(await seqs("action=ipam.prefix.")).toEqual(expected((r) => r.draft.action.startsWith("ipam.prefix.")));
    expect(await seqs("action=jobs.")).toEqual(expected((r) => r.draft.action.startsWith("jobs.")));
    // An exact action does not match its longer neighbours.
    expect(await seqs("action=ipam.prefix")).toEqual([]);

    expect(await seqs("object=prefix")).toEqual(expected((r) => r.draft.objects?.some((o) => o.kind === "prefix") ?? false));
    expect(await seqs(`object=prefix:${AUDIT_SEED_IDS.prefixIot}`)).toEqual(
      expected((r) => r.draft.objects?.some((o) => o.kind === "prefix" && o.id === AUDIT_SEED_IDS.prefixIot) ?? false),
    );
    expect((await seqs(`object=job:${MOCK_JOB_IDS.moveRolledBack}`)).length).toBeGreaterThan(0);

    expect(await seqs("outcome=denied")).toEqual(expected((r) => r.draft.outcome.kind === "denied"));
    expect(await seqs("outcome=failed")).toEqual(expected((r) => r.draft.outcome.kind === "failed"));
    expect(await seqs("outcome=success")).toEqual(expected((r) => r.draft.outcome.kind === "success"));
    expect((await seqs("outcome=failed")).length).toBeGreaterThanOrEqual(2);

    // `from` is inclusive, `to` exclusive.
    const pivot = audit.records[12]?.at ?? "";
    expect(await seqs(`from=${pivot}`)).toEqual(expected((r) => Date.parse(r.at) >= Date.parse(pivot)));
    expect(await seqs(`to=${pivot}`)).toEqual(expected((r) => Date.parse(r.at) < Date.parse(pivot)));
    const lo = audit.records[5]?.at ?? "";
    const hi = audit.records[20]?.at ?? "";
    expect(await seqs(`from=${lo}&to=${hi}`)).toEqual(expected((r) => Date.parse(r.at) >= Date.parse(lo) && Date.parse(r.at) < Date.parse(hi)));

    // Filters combine with AND.
    expect(await seqs(`action=ipam.&principal=user:${MOCK_USER_IDS.sam}&outcome=success`)).toEqual(
      expected(
        (r) =>
          r.draft.action.startsWith("ipam.") &&
          r.principal.kind === "user" &&
          r.principal.id === MOCK_USER_IDS.sam &&
          r.draft.outcome.kind === "success",
      ),
    );
  });

  it("refuses malformed filters", async () => {
    const invalid = async (query: string, parameter: string) => {
      const problem = expectProblem(await get(`/api/v1/audit?${query}`), 400, "sys.invalid_query");
      expect(problem.params).toEqual({ parameter });
    };
    await invalid("action=Not%20An%20Action", "action");
    await invalid("action=ipam", "action");
    await invalid("action=.", "action");
    await invalid("object=thing", "object");
    await invalid("object=prefix:not-a-uuid", "object");
    await invalid("outcome=maybe", "outcome");
    await invalid("from=yesterday", "from");
    await invalid("to=2026-10-09", "to");
    await invalid("order=up", "order");
    await invalid("colour=red", "colour");
    await invalid("action=ipam.&action=jobs.", "action");
    await invalid("at_least=soon", "at_least");
    await invalid("limit=0", "limit");
    await invalid("limit=1001", "limit");
    await invalid("limit=ten", "limit");
    expectProblem(await get("/api/v1/audit?cursor=%25%25"), 400, "sys.invalid_cursor");
  });

  it("returns one record by sequence number", async () => {
    const answer = await get<AuditRecord>("/api/v1/audit/3");
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual(audit.records[2]);
    const missing = expectProblem(await get(`/api/v1/audit/${audit.records.length + 1}`), 404, "sys.audit.not_found");
    expect(missing.params).toEqual({ seq: String(audit.records.length + 1) });
    for (const bad of ["0", "abc", "-1", "1.5", "18446744073709551616"]) {
      expect(expectProblem(await get(`/api/v1/audit/${bad}`), 400, "sys.invalid_query").params).toEqual({ parameter: "seq" });
    }
    // 18446744073709551615 is a valid number that no record has.
    expectProblem(await get("/api/v1/audit/18446744073709551615"), 404, "sys.audit.not_found");
  });
});

// ---------------------------------------------------------------------------------
// Audit: appending and verifying the chain

describe("audit chain", () => {
  it("verifies the seeded chain", async () => {
    const answer = await get<AuditVerifyReport>("/api/v1/audit/verify");
    expect(answer.status).toBe(200);
    const last = audit.records.at(-1);
    expect(answer.body).toEqual({
      intact: true,
      checked: audit.records.length,
      head: { seq: last?.seq, hash: last?.hash },
      store_head: last?.seq,
      revision: db.revision,
    });
    expect(answer.body.first_break).toBeUndefined();
  });

  it("shows a record appended by another module in the list and in the verification", async () => {
    const before = audit.records.length;
    const revision = db.revision;
    const seq = appendAudit({
      action: "ipam.host.create",
      objects: [{ kind: "host", id: MOCK_HOST_IDS.plugKitchen }],
      changes: [{ field: "name", old: null, new: "plug-kitchen.example.test" }],
      context: { source: "test" },
    });
    expect(seq).toBe(before + 1);
    expect(db.revision).toBe(revision + 1);
    expect(db.journal.at(-1)).toMatchObject({ topic: "audit", data: { audit: [seq] } });

    const list = await get<Page<AuditRecord>>("/api/v1/audit?limit=1");
    const record = list.body.items[0];
    expect(record).toMatchObject({
      seq,
      draft: { action: "ipam.host.create", outcome: { kind: "success" }, details: { context: { source: "test" } } },
      principal: { kind: "user", id: MOCK_USER_IDS.alex, strength: "passkey" },
      prev: audit.records[before - 1]?.hash,
      revision: db.revision,
    });
    expect((await get<AuditRecord>(`/api/v1/audit/${seq}`)).body).toEqual(record);
    expect((await get<Page<AuditRecord>>(`/api/v1/audit?object=host:${MOCK_HOST_IDS.plugKitchen}`)).body.items.map((r) => r.seq)).toEqual([seq]);

    const report = (await get<AuditVerifyReport>("/api/v1/audit/verify")).body;
    expect(report).toMatchObject({ intact: true, checked: before + 1, head: { seq, hash: record?.hash }, store_head: seq });
    expect(principalNow()).toMatchObject({ kind: "user", id: MOCK_USER_IDS.alex });
  });

  it("appends with an explicit principal, outcome and time", async () => {
    const at = Date.now() - 2 * HOUR;
    const seq = appendAudit({
      action: "jobs.job.roll_back",
      principal: { kind: "system", component: "jobs" },
      outcome: { kind: "failed", code: "jobs.timeout" },
      at,
      source_ip: null,
    });
    const record = audit.records.at(-1);
    expect(record).toMatchObject({ seq, at: new Date(at).toISOString(), principal: { kind: "system", component: "jobs" } });
    expect(record?.draft.source_ip).toBeNull();
    expect(verifyAudit().intact).toBe(true);
    expect((await get<Page<AuditRecord>>("/api/v1/audit?outcome=failed&principal=system:jobs")).body.items.map((r) => r.seq)).toContain(seq);
  });

  it("reports a record with an altered hash after tamperAuditRecord", async () => {
    tamperAuditRecord(5);
    const report = (await get<AuditVerifyReport>("/api/v1/audit/verify")).body;
    expect(report.intact).toBe(false);
    expect(report.first_break).toMatchObject({ seq: 5, code: "sys.audit.bad_hash" });
    expect(report.first_break?.detail).toContain("5");
    expect(report.checked).toBe(4);
    expect(report.head).toEqual({ seq: 4, hash: audit.records[3]?.hash });
    expect(report.store_head).toBe(audit.records.length);
    // The list still works.
    expect((await get<Page<AuditRecord>>("/api/v1/audit")).status).toBe(200);
    expect(() => tamperAuditRecord(9999)).toThrow(/no audit record 9999/);
    // A fresh reset repairs the log.
    resetMockDb("signed-in");
    expect(verifyAudit().intact).toBe(true);
  });

  it("finds a gap, a broken link and a changed record", async () => {
    const original = [...audit.records];

    audit.records.splice(2, 1);
    let report = (await get<AuditVerifyReport>("/api/v1/audit/verify")).body;
    expect(report).toMatchObject({ intact: false, checked: 2, first_break: { seq: 4, code: "sys.audit.gap" }, head: { seq: 2 } });

    audit.records = original.map((r) => structuredClone(r));
    const fourth = audit.records[3];
    if (fourth) fourth.prev = "f".repeat(64);
    report = (await get<AuditVerifyReport>("/api/v1/audit/verify")).body;
    expect(report).toMatchObject({ intact: false, checked: 3, first_break: { seq: 4, code: "sys.audit.broken_link" } });

    audit.records = original.map((r) => structuredClone(r));
    const second = audit.records[1];
    if (second) second.draft.details = { changes: [], context: { note: "edited" } };
    report = (await get<AuditVerifyReport>("/api/v1/audit/verify")).body;
    expect(report).toMatchObject({ intact: false, checked: 1, first_break: { seq: 2, code: "sys.audit.bad_hash" } });
  });

  it("verifies an empty log", async () => {
    resetMockDb("setup");
    const report = verifyAudit();
    expect(report).toEqual({ intact: true, checked: 0, head: { seq: 0, hash: "0".repeat(64) }, store_head: 0, revision: db.revision });
  });
});
