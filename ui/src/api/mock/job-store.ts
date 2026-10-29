// The jobs of the mock API (IPAM-17). A small copy of the job engine of `tenko-jobs`:
// state machine, manual steps, manual undo tasks, deadlines, cancel and the group slots,
// fed by a clock the callers pass in so that the seeds can be built in the past.
//
// What the mock simplifies: the engine runs in the request (a cancel rolls the job back at
// once, completing a step runs the following steps at once), an "automatic" step finishes
// the moment it starts unless it is marked `slow` (the ticker finishes those), and the
// step parameters are not kept (the mock keeps the manual task of each step instead).
import type {
  AssignmentMode,
  CodedError,
  Job,
  JobPreview,
  JobState,
  JobSummary,
  ManualTask,
  ObjectRef,
  Principal,
  StepPreview,
  StepRecord,
  StepState,
  Transition,
} from "../types";
import { SEED_ROLLBACK_NOTES, appendAudit, principalNow } from "./audit-store";
import { db, onMockReset, recordEvent, type MockEvent } from "./db";
import { MOCK_USER_IDS } from "./fixtures";
import { Problem } from "./reply";
import { MINUTE, iso, randomId } from "./util";

// ---------------------------------------------------------------------------------
// Constants

/** The runner (node) that owns every started job. */
export const MOCK_RUNNER = 1;
/** Longest note of a completed step, in bytes (`jobs.note.too_long`). */
export const MAX_NOTE_BYTES = 4096;
/** Jobs the list keeps; the ticker drops the oldest finished ones beyond this. */
export const KEEP_JOBS = 30;
/** Parallelism of a group whose jobs carry no `group_limit` (the engine default). */
const DEFAULT_GROUP_LIMIT = 10;

/** Fixed ids of the hosts the seed jobs move (UUID syntax, like the real ones). */
export const MOCK_HOST_IDS = {
  thermostat1: "0190d1c2-0000-7000-8000-0000000b0001",
  plugKitchen: "0190d1c2-0000-7000-8000-0000000b0002",
  camDoor: "0190d1c2-0000-7000-8000-0000000b0003",
  nas: "0190d1c2-0000-7000-8000-0000000b0004",
} as const;

/** Fixed ids of the seed jobs. */
export const MOCK_JOB_IDS = {
  /** A move job waiting for the DHCP step. */
  moveWaiting: "0190d1c2-0000-7000-8000-0000000c0001",
  /** A move job of the same group, still queued. */
  moveQueued: "0190d1c2-0000-7000-8000-0000000c0002",
  /** An import that runs. */
  importRunning: "0190d1c2-0000-7000-8000-0000000c0003",
  /** An inline `ipam.apply` job that succeeded. */
  applySucceeded: "0190d1c2-0000-7000-8000-0000000c0004",
  /** A move job that failed on `l2.move` and was rolled back. */
  moveRolledBack: "0190d1c2-0000-7000-8000-0000000c0005",
  /** An `ipam.apply` job that was cancelled while queued. */
  applyCancelled: "0190d1c2-0000-7000-8000-0000000c0006",
} as const;

/**
 * The parallelism group of the seed move jobs: the server names a move group `ipam.move.` and
 * the 32 hex digits of a UUID (crates/tenko-ipam/src/moves/submit.rs); this one is the id of the
 * target prefix, 198.51.100.0/24.
 */
export const MOCK_MOVE_GROUP = "ipam.move.0190d1c200007000800000000a0002";

/** The prefix an `ipam.apply` seed job changes, and the target of the seed moves (the IoT network). */
const SEED_PREFIX_ID = "0190d1c2-0000-7000-8000-0000000a0002";
/** The VRF `default` and the VLAN 30 of the IPAM seed, the target of the seed moves. */
const SEED_VRF_ID = "0190d1c2-0000-7000-8000-000000020001";
const SEED_VLAN_ID = "0190d1c2-0000-7000-8000-00000004001e";

const SYSTEM_JOBS: Principal = { kind: "system", component: "jobs" };
const SYSTEM_IMPORT: Principal = { kind: "system", component: "import" };

// ---------------------------------------------------------------------------------
// Types

/** How the mock engine treats one step. */
export interface StepPlan {
  /** The task a person does; null for a step the engine runs itself. */
  manual: ManualTask | null;
  /** An engine step that takes a while: it stays running until the ticker finishes it. */
  slow: boolean;
  /** An engine step that fails with this error when it runs (a scripted failure). */
  failsWith: CodedError | null;
  /** The output an engine step keeps when it finishes (hex), as the server stores it. */
  output: string | null;
  /** An engine step whose undo fails: the rollback asks a person (`jobs.undo.step`). */
  undoFails: boolean;
}

export interface MockJobRecord {
  job: Job;
  transitions: Transition[];
  /** What the job meant to do, computed at submission; null for jobs without a preview. */
  preview: JobPreview | null;
  /** One entry per step. */
  plan: StepPlan[];
}

export const jobStore: { jobs: MockJobRecord[] } = { jobs: [] };

export interface MockStepInput {
  /** The step kind, for example `ipam.move.dhcp`. */
  kind: string;
  /** The task a person does. */
  manual?: ManualTask | null;
  /** The engine runs the step itself. A step needs a `manual` task or this. */
  automatic: boolean;
  /**
   * Message key of the step summary in the preview. A manual step uses the instruction of its
   * task, as the server does; any other step `jobs.step.<kind>`.
   */
  summary?: string;
  /** Message arguments of the step summary in the preview (the manual task's by default). */
  args?: Record<string, string>;
  /** Objects the step changes, for the preview. */
  changes?: ObjectRef[];
  /** An automatic step that stays running until the ticker finishes it. */
  slow?: boolean;
  /** An automatic step that fails with this error when it runs. */
  failsWith?: CodedError | null;
  /** The output an automatic step keeps when it finishes (hex). */
  output?: string | null;
  /** An automatic step whose undo fails, so the rollback asks a person. */
  undoFails?: boolean;
}

export interface MockJobInput {
  kind: string;
  /** Message key of the title (`ipam.move.title`); the UI translates it. */
  title: string;
  targets: ObjectRef[];
  group?: string;
  /** Parallelism of the group; the jobs of one group carry the same value. */
  groupLimit?: number;
  timeoutSecs: number;
  steps: MockStepInput[];
  /** `false` for a job without a preview; default `true`. */
  preview?: boolean;
}

export interface CreateJobOptions {
  /** The first steps were executed by the caller already: they finish when the job starts. */
  startedSteps?: number;
}

type JobAction =
  | "start"
  | "wait"
  | "resume"
  | "complete"
  | "roll_back"
  | "cancel"
  | "finish_rollback"
  | "finish_cancel"
  | "fail";

/** Who acts and when; engine rows made by the runner use the jobs component. */
interface Ctx {
  now: number;
  by: Principal;
}

const NEXT_STATE: Record<JobState, Partial<Record<JobAction, JobState>>> = {
  queued: { start: "running", cancel: "cancelled" },
  running: { wait: "waiting", complete: "succeeded", roll_back: "rolling_back", cancel: "rolling_back" },
  waiting: { resume: "running", roll_back: "rolling_back", cancel: "rolling_back" },
  rolling_back: { finish_rollback: "rolled_back", finish_cancel: "cancelled", fail: "failed" },
  succeeded: {},
  failed: {},
  rolled_back: {},
  cancelled: {},
};

const TERMINAL: readonly JobState[] = ["succeeded", "failed", "rolled_back", "cancelled"];
/** States in which a job holds a slot of its group. */
const HOLDING: readonly JobState[] = ["running", "waiting", "rolling_back"];

/** Errors the engine puts on a step whose work may have had effects: such steps are undone. */
const ABORT_CODES: readonly string[] = [
  "jobs.cancelled",
  "jobs.step.interrupted",
  "jobs.step.deadline_passed",
  "jobs.step.timeout",
  "jobs.timeout",
];

// ---------------------------------------------------------------------------------
// Errors

function pascal(state: string): string {
  return state
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

/** `jobs.not_found` (404). */
function notFound(id: string): Problem {
  return new Problem("jobs.not_found", { status: 404, detail: `job ${id} not found`, params: { job: id } });
}

/** `jobs.step.not_found` (404). */
function stepNotFound(id: string, step: number): Problem {
  return new Problem("jobs.step.not_found", {
    status: 404,
    detail: `job ${id} has no step ${step}`,
    params: { job: id, step: String(step) },
  });
}

/** `jobs.invalid_transition` (409): the action is not allowed in the job's state. */
function invalidTransition(from: JobState, action: string): Problem {
  return new Problem("jobs.invalid_transition", {
    status: 409,
    detail: `cannot ${action} a job that is ${pascal(from)}`,
    params: { from: pascal(from), action },
  });
}

function cancelledError(): CodedError {
  return { code: "jobs.cancelled", status: 409, title: "Job cancelled", detail: "the job was cancelled" };
}

function timeoutError(): CodedError {
  return { code: "jobs.timeout", status: 504, title: "Job timed out", detail: "job timed out" };
}

function deadlinePassed(step: number): CodedError {
  return {
    code: "jobs.step.deadline_passed",
    status: 504,
    title: "Step deadline passed",
    detail: `step ${step} was still waiting at its deadline`,
    params: { step: String(step) },
  };
}

// ---------------------------------------------------------------------------------
// The engine

function isTerminal(state: JobState): boolean {
  return TERMINAL.includes(state);
}

function ref(rec: MockJobRecord): ObjectRef {
  return { kind: "job", id: rec.job.id };
}

/** Appends one row to the transition log; the job state is the one after the change. */
function log(rec: MockJobRecord, ctx: Ctx, fields: Omit<Transition, "seq" | "at" | "by" | "state">): Transition {
  const row: Transition = { seq: rec.transitions.length, at: iso(ctx.now), by: ctx.by, state: rec.job.state, ...fields };
  rec.transitions.push(row);
  return row;
}

function jobAction(rec: MockJobRecord, ctx: Ctx, action: JobAction, extra: { runner?: number } = {}): void {
  const job = rec.job;
  const from = job.state;
  const to = NEXT_STATE[from][action];
  if (!to) throw invalidTransition(from, action);
  job.state = to;
  if (isTerminal(to)) job.finished = iso(ctx.now);
  log(rec, ctx, { event: "job", action, from, ...extra });
}

const FINISHED_STEP_STATES: readonly string[] = ["done", "skipped", "failed", "compensated", "compensation_failed"];

/** Sets a step state and logs it; returns the row, so that a note can be attached. */
function setStep(rec: MockJobRecord, ctx: Ctx, index: number, state: StepState): Transition {
  const step = rec.job.steps[index];
  if (!step) throw new Error(`no step ${index}`);
  step.state = state;
  if (FINISHED_STEP_STATES.includes(state.state)) step.finished = iso(ctx.now);
  return log(rec, ctx, { event: "step", step: index, step_state: state });
}

function beginStep(rec: MockJobRecord, ctx: Ctx, index: number): void {
  const step = rec.job.steps[index];
  if (!step) return;
  step.attempts = (step.attempts ?? 0) + 1;
  step.started ??= iso(ctx.now);
  setStep(rec, ctx, index, { state: "running" });
}

/** The first step that is neither done nor skipped. */
function currentStep(job: Job): number | null {
  const index = job.steps.findIndex((s) => s.state.state !== "done" && s.state.state !== "skipped");
  return index < 0 ? null : index;
}

/** When the job times out: the start of the first step plus the job timeout. */
function jobDeadline(rec: MockJobRecord): number | null {
  const started = rec.job.steps[0]?.started ?? rec.job.started;
  if (!started) return null;
  return Date.parse(started) + rec.job.spec.timeout * 1000;
}

/** The deadline a manual step announces: the job deadline, or for the observation the timeout from now. */
function manualDeadline(rec: MockJobRecord, ctx: Ctx, index: number): string | null {
  const kind = rec.job.steps[index]?.kind;
  if (kind === "ipam.move.observe" || kind === "observe") return iso(ctx.now + rec.job.spec.timeout * 1000);
  const deadline = jobDeadline(rec);
  return deadline === null ? null : iso(deadline);
}

/**
 * Takes every decision that needs no person: starts the next step, runs automatic steps,
 * parks at a manual step, completes the job, or continues a rollback.
 */
function advance(rec: MockJobRecord, ctx: Ctx): void {
  for (;;) {
    const job = rec.job;
    if (job.state === "rolling_back") {
      rollback(rec, ctx);
      return;
    }
    if (job.state !== "running") return;
    const index = currentStep(job);
    if (index === null) {
      jobAction(rec, ctx, "complete");
      return;
    }
    const step = job.steps[index];
    const plan = rec.plan[index];
    // A running step finishes elsewhere (the ticker); anything else is not expected here.
    if (!step || !plan || step.state.state !== "pending") return;
    beginStep(rec, ctx, index);
    if (plan.manual) {
      const deadline = manualDeadline(rec, ctx, index);
      setStep(rec, ctx, index, { state: "waiting_for_manual", data: { task: plan.manual, deadline } });
      jobAction(rec, ctx, "wait");
      return;
    }
    if (plan.failsWith) {
      failStep(rec, ctx, index, plan.failsWith);
      return;
    }
    if (plan.slow) return;
    if (plan.output) step.output = plan.output;
    setStep(rec, ctx, index, { state: "done" });
  }
}

/** A running step fails with its own error: no effect to undo, the job rolls back. */
function failStep(rec: MockJobRecord, ctx: Ctx, index: number, error: CodedError): void {
  setStep(rec, ctx, index, { state: "failed", data: { error } });
  rec.job.error ??= error;
  jobAction(rec, ctx, "roll_back");
  rollback(rec, ctx);
}

/**
 * Walks the steps in reverse: a step that ran is compensated, or becomes a manual undo task
 * when its task names an undo message. The job rolls back for good once no undo task waits.
 */
function rollback(rec: MockJobRecord, ctx: Ctx): void {
  const job = rec.job;
  for (let index = job.steps.length - 1; index >= 0; index -= 1) {
    const step = job.steps[index];
    const plan = rec.plan[index];
    if (!step || !plan) continue;
    const state = step.state;
    let effects = false;
    if (state.state === "done" || state.state === "running" || state.state === "waiting_for_observation") {
      effects = true;
    } else if (state.state === "failed") {
      effects = ABORT_CODES.includes(state.data.error.code);
    }
    if (!effects) continue;
    const task = plan.manual;
    if (task?.undo) {
      const undo: ManualTask = { instruction: task.undo, args: { ...task.args } };
      setStep(rec, ctx, index, { state: "waiting_for_manual", data: { task: undo, deadline: null } });
    } else if (plan.undoFails) {
      // The handler answered "not compensable": a generic undo task names the step.
      const undo: ManualTask = { instruction: "jobs.undo.step", args: { step: String(index), kind: step.kind } };
      setStep(rec, ctx, index, { state: "compensating" });
      setStep(rec, ctx, index, { state: "waiting_for_manual", data: { task: undo, deadline: null } });
    } else {
      setStep(rec, ctx, index, { state: "compensating" });
      setStep(rec, ctx, index, { state: "compensated" });
    }
  }
  if (job.steps.some((s) => s.state.state === "waiting_for_manual")) return;
  jobAction(rec, ctx, job.error?.code === "jobs.cancelled" ? "finish_cancel" : "finish_rollback");
}

/** Aborts the current step if it was running or waiting. */
function abortCurrent(rec: MockJobRecord, ctx: Ctx, error: CodedError): void {
  const index = currentStep(rec.job);
  if (index === null) return;
  const state = rec.job.steps[index]?.state.state;
  if (state === "running" || state === "waiting_for_observation" || state === "waiting_for_manual") {
    setStep(rec, ctx, index, { state: "failed", data: { error } });
  }
}

function startRecord(rec: MockJobRecord, ctx: Ctx): void {
  const job = rec.job;
  job.runner = MOCK_RUNNER;
  log(rec, ctx, { event: "claimed", runner: MOCK_RUNNER });
  job.started = iso(ctx.now);
  jobAction(rec, ctx, "start", { runner: MOCK_RUNNER });
  advance(rec, ctx);
}

/** Completes a manual task, or a manual undo task of a job that rolls back. */
function completeStep(rec: MockJobRecord, ctx: Ctx, index: number, note: string | null): void {
  const job = rec.job;
  const step = job.steps[index];
  if (!step) throw stepNotFound(job.id, index);
  if (step.state.state !== "waiting_for_manual" || (job.state !== "waiting" && job.state !== "rolling_back")) {
    throw invalidTransition(job.state, "complete_manual");
  }
  const engine: Ctx = { now: ctx.now, by: SYSTEM_JOBS };
  if (job.state === "waiting") {
    const row = setStep(rec, ctx, index, { state: "done" });
    if (note) row.note = note;
    jobAction(rec, ctx, "resume");
  } else {
    const row = setStep(rec, ctx, index, { state: "compensated" });
    if (note) row.note = note;
  }
  advance(rec, engine);
}

/** Asks to cancel: a queued job is cancelled at once, a running or waiting one rolls back. */
function cancelRecord(rec: MockJobRecord, ctx: Ctx): void {
  const job = rec.job;
  const stamp = { at: iso(ctx.now), by: ctx.by };
  if (job.state === "queued") {
    job.cancel_requested = stamp;
    job.error = cancelledError();
    jobAction(rec, ctx, "cancel");
    return;
  }
  if (job.state !== "running" && job.state !== "waiting") throw invalidTransition(job.state, "cancel");
  if (job.cancel_requested) return;
  job.cancel_requested = stamp;
  log(rec, ctx, { event: "cancel_requested" });
  // The runner acts on it at once in the mock.
  const engine: Ctx = { now: ctx.now, by: SYSTEM_JOBS };
  abortCurrent(rec, engine, cancelledError());
  job.error = cancelledError();
  jobAction(rec, engine, "cancel");
  rollback(rec, engine);
}

/** The time and error of the next deadline of a running or waiting job, if it has one. */
function nextDeadline(rec: MockJobRecord): { at: number; error: CodedError } | null {
  const job = rec.job;
  if (job.state !== "running" && job.state !== "waiting") return null;
  const jobAt = jobDeadline(rec);
  let stepAt: number | null = null;
  let stepIndex = -1;
  if (job.state === "waiting") {
    stepIndex = currentStep(job) ?? -1;
    const state = job.steps[stepIndex]?.state;
    if (state && (state.state === "waiting_for_manual" || state.state === "waiting_for_observation")) {
      const deadline = state.data.deadline;
      if (deadline) stepAt = Date.parse(deadline);
    }
  }
  if (jobAt !== null && (stepAt === null || jobAt <= stepAt)) return { at: jobAt, error: timeoutError() };
  if (stepAt !== null) return { at: stepAt, error: deadlinePassed(stepIndex) };
  return null;
}

/** Rolls the job back when a deadline has passed; returns whether it did. */
function expireRecord(rec: MockJobRecord, ctx: Ctx): boolean {
  const due = nextDeadline(rec);
  if (!due || ctx.now < due.at) return false;
  abortCurrent(rec, ctx, due.error);
  rec.job.error ??= due.error;
  jobAction(rec, ctx, "roll_back");
  rollback(rec, ctx);
  return true;
}

/** Finishes the running step of a slow job and goes on with the next one. */
function tickRecord(rec: MockJobRecord, ctx: Ctx): void {
  const index = currentStep(rec.job);
  if (index !== null && rec.job.steps[index]?.state.state === "running") {
    setStep(rec, ctx, index, { state: "done" });
  }
  advance(rec, ctx);
}

// ---------------------------------------------------------------------------------
// Groups

function limitOf(rec: MockJobRecord): number {
  return Math.max(1, rec.job.spec.group_limit ?? DEFAULT_GROUP_LIMIT);
}

/** Starts the queued jobs of a group, oldest first, while a slot below the limit is free. */
function scheduleGroup(group: string, now: number): MockJobRecord[] {
  const started: MockJobRecord[] = [];
  const inGroup = jobStore.jobs.filter((r) => r.job.spec.group === group);
  const queued = inGroup
    .filter((r) => r.job.state === "queued")
    .sort((a, b) => Date.parse(a.job.created.at) - Date.parse(b.job.created.at) || inGroup.indexOf(b) - inGroup.indexOf(a));
  for (const rec of queued) {
    const used = inGroup.filter((r) => HOLDING.includes(r.job.state)).length;
    if (used >= limitOf(rec)) break;
    startRecord(rec, { now, by: SYSTEM_JOBS });
    started.push(rec);
  }
  return started;
}

/** The queued jobs that start because `rec` reached a final state and freed its slot. */
function releaseSlot(rec: MockJobRecord, now: number): MockJobRecord[] {
  const group = rec.job.spec.group;
  if (!group || !isTerminal(rec.job.state)) return [];
  return scheduleGroup(group, now);
}

// ---------------------------------------------------------------------------------
// Building jobs

/** The preview key of a step kind: `dhcp.manual` becomes `jobs.step.dhcp_manual`. */
function stepSummaryKey(kind: string): string {
  return `jobs.step.${kind.replace(/\./g, "_")}`;
}

function previewOf(input: MockJobInput, plan: StepPlan[]): JobPreview {
  const steps = input.steps.map((step, index): StepPreview => {
    const manual = plan[index]?.manual ?? null;
    const preview: StepPreview = {
      summary: step.summary ?? manual?.instruction ?? stepSummaryKey(step.kind),
      args: { ...(step.args ?? manual?.args ?? {}) },
      changes: step.changes ? step.changes.map((c) => ({ ...c })) : [],
      warnings: [],
    };
    if (manual) preview.manual = structuredClone(manual);
    return preview;
  });
  return { steps, warnings: [] };
}

/** Records the submission of a job: state `queued`, every step `pending`. */
function submit(input: MockJobInput, ctx: Ctx, options: CreateJobOptions & { id?: string } = {}): MockJobRecord {
  const forced = Math.max(0, options.startedSteps ?? 0);
  const plan = input.steps.map((step, index): StepPlan => {
    const output = step.output ?? null;
    const undoFails = !!step.undoFails;
    if (index < forced) return { manual: null, slow: false, failsWith: null, output, undoFails };
    const manual = step.manual ?? null;
    if (!manual && !step.automatic) {
      throw new Error(`step ${index} (${step.kind}) is neither automatic nor a manual task`);
    }
    return {
      manual,
      slow: !manual && !!step.slow,
      failsWith: manual ? null : (step.failsWith ?? null),
      output: manual ? null : output,
      undoFails: manual ? false : undoFails,
    };
  });
  const spec: Job["spec"] = {
    kind: input.kind,
    title: input.title,
    targets: input.targets.map((t) => ({ ...t })),
    steps: input.steps.map((s) => ({ kind: s.kind, params: "", timeout: null })),
    timeout: input.timeoutSecs,
  };
  if (input.group) {
    spec.group = input.group;
    if (input.groupLimit !== undefined) spec.group_limit = input.groupLimit;
  }
  const steps: StepRecord[] = input.steps.map((s, index) => ({
    index,
    kind: s.kind,
    state: { state: "pending" },
    attempts: 0,
  }));
  const job: Job = {
    id: options.id ?? randomId(),
    spec,
    state: "queued",
    created: { at: iso(ctx.now), by: ctx.by },
    steps,
    revision: db.revision,
  };
  const rec: MockJobRecord = {
    job,
    transitions: [],
    plan,
    preview: input.preview === false ? null : previewOf(input, plan),
  };
  log(rec, ctx, { event: "submitted" });
  return rec;
}

/** Announces the changed jobs on the `jobs` topic and stamps the revision on them. */
function commitJobs(records: Iterable<MockJobRecord>, deleted: ObjectRef[] = []): MockEvent {
  const list = [...new Set(records)];
  const event = recordEvent("jobs", { objects: list.map(ref), deleted });
  for (const rec of list) rec.job.revision = event.id ?? db.revision;
  return event;
}

/**
 * Creates a job that runs the way the engine would run it: the job starts at once, its
 * first `startedSteps` steps and every automatic step finish, and it waits at the first
 * manual step. A job of a full group (or behind a queued one) stays `queued` and starts
 * when a slot frees up. Records the transitions and the event; returns the id.
 */
export function createJob(spec: MockJobInput, options: CreateJobOptions = {}): string {
  const now = Date.now();
  const rec = submit(spec, { now, by: principalNow() }, options);
  jobStore.jobs.unshift(rec);
  const touched: MockJobRecord[] = [rec];
  if (spec.group) touched.push(...scheduleGroup(spec.group, now));
  else startRecord(rec, { now, by: SYSTEM_JOBS });
  commitJobs(touched);
  return rec.job.id;
}

export interface InlineJobInput {
  /** Job kind, for example `ipam.apply`. */
  kind: string;
  /** Message key of the title (`jobs.title.ipam_apply`); the UI translates it. */
  title: string;
  targets: ObjectRef[];
}

function inlineRecord(input: InlineJobInput, ctx: Ctx, id?: string): MockJobRecord {
  const rec = submit(
    {
      kind: input.kind,
      title: input.title,
      targets: input.targets,
      timeoutSecs: 60,
      steps: [{ kind: input.kind, automatic: true }],
      preview: false,
    },
    ctx,
    { id },
  );
  startRecord(rec, { now: ctx.now, by: SYSTEM_JOBS });
  return rec;
}

/** Records a finished inline job and announces it on the `jobs` topic; returns its id. */
export function recordInlineJob(input: InlineJobInput): string {
  const rec = inlineRecord(input, { now: Date.now(), by: principalNow() });
  jobStore.jobs.unshift(rec);
  commitJobs([rec]);
  return rec.job.id;
}

/**
 * Records an inline job that finished in the past, without an event (a history for the list):
 * submitted by `by` at `created`, done at `finished` (milliseconds); returns its id.
 */
export function recordPastJob(input: InlineJobInput, at: { created: number; finished: number; by: Principal }): string {
  const rec = submit(
    { kind: input.kind, title: input.title, targets: input.targets, timeoutSecs: 60, steps: [{ kind: input.kind, automatic: true }], preview: false },
    { now: at.created, by: at.by },
  );
  startRecord(rec, { now: at.finished, by: SYSTEM_JOBS });
  rec.job.revision = db.revision;
  jobStore.jobs.push(rec);
  return rec.job.id;
}

// ---------------------------------------------------------------------------------
// Move jobs

/**
 * The step kinds of a move job, in the order of the job (crates/tenko-ipam/src/moves/steps.rs).
 * The job has a prepare step when Tenko DHCP follows the client, an intent step, a DHCP step for a
 * reserved host, a DNS step for an address with a name, a device step for a static host, the wait
 * for the short lease, then the layer 2 change, the observation and the cleanup.
 */
export const MOVE_STEP = {
  prepare: "ipam.move.prepare",
  lease: "ipam.move.lease",
  intent: "ipam.move.intent",
  dhcp: "ipam.move.dhcp",
  dns: "ipam.move.dns",
  device: "ipam.move.device",
  l2: "ipam.move.l2",
  controller: "ipam.move.controller",
  nudge: "ipam.move.nudge",
  observe: "ipam.move.observe",
  cleanup: "ipam.move.cleanup",
} as const;

/**
 * The standard manual tasks of a step kind (the UI translates the keys). The manual steps of a
 * move have no undo task: a rollback never waits for a person.
 */
const TASK_KEYS: Readonly<Record<string, { instruction: string; undo?: string }>> = {
  [MOVE_STEP.lease]: { instruction: "ipam.move.task.short_lease" },
  [MOVE_STEP.dhcp]: { instruction: "ipam.move.task.dhcp" },
  [MOVE_STEP.dns]: { instruction: "ipam.move.task.dns" },
  [MOVE_STEP.device]: { instruction: "ipam.move.task.device" },
  [MOVE_STEP.l2]: { instruction: "ipam.move.task.l2" },
  [MOVE_STEP.observe]: { instruction: "ipam.move.task.observe" },
};

/**
 * The manual task of a step kind with the given message arguments. The server attaches the same
 * arguments to every task: `prefix`, `cidr`, `vrf`, `old_ip`, `new_ip`, `address`, `new_address`,
 * and when known `vlan`, `vid`, `host` (the name) and `mac`; the DNS task adds `name` and the
 * observation `timeout_secs`.
 */
export function manualTask(kind: string, args: Record<string, string>): ManualTask {
  const keys = TASK_KEYS[kind];
  if (!keys) throw new Error(`no manual task for the step kind ${kind}`);
  const task: ManualTask = { instruction: keys.instruction, args: { ...args } };
  if (keys.undo) task.undo = keys.undo;
  return task;
}

/** What the steps of one moved address are built from; the fields are those of the server's move item. */
export interface MoveArgs {
  /** The target prefix and VRF (identifiers) and the target network. */
  prefix: string;
  cidr: string;
  vrf: string;
  oldIp: string;
  newIp: string;
  /** The address that moves and the identifier of the new address. */
  address: string;
  newAddress: string;
  vlan?: string | null;
  vid?: number | string | null;
  /** The host name. */
  host?: string | null;
  mac?: string | null;
  /** The DNS name of the address; a name adds the DNS step. */
  dnsName?: string | null;
  /** `reserved` adds the DHCP step, `static` the device step. */
  mode?: AssignmentMode | null;
  /** The observation timeout in seconds. */
  timeoutSecs: number;
  /** The L2 step as the preview decided it; without it the L2 step is the generic manual task. */
  l2?: MockMoveL2 | null;
  /** Tenko DHCP follows the client: the job starts with the prepare step. */
  prepare?: boolean;
  /** The job waits for the client's renewal with the short lease before the L2 change. */
  shortLease?: { secs: number; nextActivity: string };
}

/** The L2 step of a mock move (crates/tenko-ipam/src/moves/l2.rs). */
export interface MockMoveL2 {
  /** `port_profile` and `client_vlan` run through the controller; `unchanged` and `shared` have no step. */
  action: "port_profile" | "client_vlan" | "manual" | "unchanged" | "shared";
  /** The message key of the manual task (`ipam.move.task.l2_*`), or of the controller step's summary. */
  key?: string;
  /** The message arguments of the L2 step (device, port, profile, network, connector, ...). */
  args?: Record<string, string>;
  /** The output of the controller step (hex-encoded JSON, see `encodeMoveL2Output`). */
  output?: string;
  /** The controller step's undo fails, so a rollback asks a person. */
  undoFails?: boolean;
  /** Changes of the step besides the moved objects (the connector). */
  changes?: ObjectRef[];
  /** The bounce or kick after the controller step (`ipam.move.nudge`): the summary key, its arguments and the output (hex). */
  nudge?: { key: string; args: Record<string, string>; output: string };
}

export interface MoveStepOptions {
  /** Objects every step changes, for the preview. */
  changes?: ObjectRef[];
  /** The `ipam.move.l2` step runs by itself (a connector moves the port) and fails with this error. */
  l2FailsWith?: CodedError;
}

/** The steps of the job of one moved address, in the order and with the arguments of the server. */
export function moveSteps(move: MoveArgs, options: MoveStepOptions = {}): MockStepInput[] {
  const base: Record<string, string> = {
    prefix: move.prefix,
    cidr: move.cidr,
    vrf: move.vrf,
    old_ip: move.oldIp,
    new_ip: move.newIp,
    address: move.address,
    new_address: move.newAddress,
  };
  if (move.vlan) base.vlan = move.vlan;
  if (move.vid !== undefined && move.vid !== null) base.vid = String(move.vid);
  if (move.host) base.host = move.host;
  if (move.mac) base.mac = move.mac;
  // The automatic steps name the addresses and the network only.
  const plain: Record<string, string> = { old_ip: move.oldIp, new_ip: move.newIp, cidr: move.cidr };
  if (base.vid !== undefined) plain.vid = base.vid;
  const changes = options.changes ?? [];
  const manual = (kind: string, args: Record<string, string>): MockStepInput => ({
    kind,
    automatic: false,
    manual: manualTask(kind, args),
    changes,
  });

  const steps: MockStepInput[] = [];
  if (move.prepare) steps.push({ kind: MOVE_STEP.prepare, automatic: true, summary: "ipam.move.step.prepare", args: plain, changes });
  steps.push({ kind: MOVE_STEP.intent, automatic: true, summary: "ipam.move.step.intent", args: plain, changes });
  if (move.mode === "reserved") steps.push(manual(MOVE_STEP.dhcp, base));
  if (move.dnsName) steps.push(manual(MOVE_STEP.dns, { ...base, name: move.dnsName }));
  if (move.mode === "static") steps.push(manual(MOVE_STEP.device, base));
  if (move.shortLease) {
    steps.push(
      manual(MOVE_STEP.lease, { ...base, short_secs: String(move.shortLease.secs), next_activity: move.shortLease.nextActivity }),
    );
  }
  const l2 = move.l2;
  if (options.l2FailsWith) {
    steps.push({
      kind: MOVE_STEP.l2,
      automatic: true,
      summary: "ipam.move.task.l2",
      args: base,
      changes,
      failsWith: options.l2FailsWith,
    });
  } else if (!l2) {
    steps.push(manual(MOVE_STEP.l2, base));
  } else if (l2.action === "port_profile" || l2.action === "client_vlan") {
    const step: MockStepInput = {
      kind: MOVE_STEP.controller,
      automatic: true,
      summary: l2.key ?? (l2.action === "port_profile" ? "ipam.move.step.controller_port" : "ipam.move.step.controller_client"),
      args: { ...plain, ...(l2.args ?? {}) },
      changes: [...changes, ...(l2.changes ?? [])],
    };
    if (l2.output) step.output = l2.output;
    if (l2.undoFails) step.undoFails = true;
    steps.push(step);
    if (l2.nudge) {
      steps.push({
        kind: MOVE_STEP.nudge,
        automatic: true,
        summary: l2.nudge.key,
        args: { ...plain, ...l2.nudge.args },
        changes: [...changes, ...(l2.changes ?? [])],
        output: l2.nudge.output,
      });
    }
  } else if (l2.action === "manual") {
    steps.push({
      kind: MOVE_STEP.l2,
      automatic: false,
      manual: { instruction: l2.key ?? "ipam.move.task.l2", args: { ...base, ...(l2.args ?? {}) } },
      changes,
    });
  }
  steps.push(
    manual(MOVE_STEP.observe, { ...base, timeout_secs: String(move.timeoutSecs) }),
    { kind: MOVE_STEP.cleanup, automatic: true, summary: "ipam.move.step.cleanup", args: plain, changes },
  );
  return steps;
}

export interface MoveJobInput {
  host: ObjectRef;
  /** The host name, for example `thermostat-1`. */
  name: string;
  /** The DNS name of the address; without one the job has no DNS step. */
  fqdn?: string;
  mac?: string;
  /** The address after the move. */
  ip: string;
  /** The address before the move. */
  oldIp: string;
  /** The target network (default: the IoT network of the IPAM seed). */
  cidr?: string;
  /** The VLAN id of the target (default 30). */
  vid?: number;
  /** The assignment mode of the host: `reserved` (default) adds a DHCP step, `static` a device step. */
  mode?: AssignmentMode;
  group?: string;
  groupLimit?: number;
  timeoutSecs?: number;
  /** The layer 2 step runs by itself (a connector moves the port) and fails with this error. */
  l2FailsWith?: CodedError;
  /** The L2 step as the preview decided it (see `MockMoveL2`); without it a generic manual task. */
  l2?: MockMoveL2;
}

/** The job input of a move, as the server builds it: kind `ipam.move`, title `ipam.move.title`. */
export function moveJobInput(move: MoveJobInput): MockJobInput {
  // Opaque identifiers of the moved address and the new one, from the host's.
  const tail = move.host.id.slice(-4);
  const args: MoveArgs = {
    prefix: SEED_PREFIX_ID,
    cidr: move.cidr ?? "198.51.100.0/24",
    vrf: SEED_VRF_ID,
    oldIp: move.oldIp,
    newIp: move.ip,
    address: `${move.host.id.slice(0, -5)}f${tail}`,
    newAddress: `${move.host.id.slice(0, -5)}e${tail}`,
    vlan: SEED_VLAN_ID,
    vid: move.vid ?? 30,
    host: move.name,
    mac: move.mac ?? null,
    dnsName: move.fqdn ?? null,
    mode: move.mode ?? "reserved",
    timeoutSecs: move.timeoutSecs ?? 43200,
    l2: move.l2 ?? null,
  };
  const stepOptions: MoveStepOptions = { changes: [move.host] };
  if (move.l2FailsWith) stepOptions.l2FailsWith = move.l2FailsWith;
  const input: MockJobInput = {
    kind: "ipam.move",
    title: "ipam.move.title",
    targets: [move.host, { kind: "prefix", id: SEED_PREFIX_ID }],
    timeoutSecs: move.timeoutSecs ?? 43200,
    steps: moveSteps(args, stepOptions),
  };
  if (move.group) input.group = move.group;
  if (move.groupLimit !== undefined) input.groupLimit = move.groupLimit;
  return input;
}

// ---------------------------------------------------------------------------------
// Reading

/** The record of a job, or undefined. */
export function findJob(id: string): MockJobRecord | undefined {
  const key = id.toLowerCase();
  return jobStore.jobs.find((r) => r.job.id === key);
}

function requireJob(id: string): MockJobRecord {
  const rec = findJob(id);
  if (!rec) throw notFound(id);
  return rec;
}

/** The document's JobSummary: derived from the job like `JobSummary::from` of the server. */
export function summarizeJob(rec: MockJobRecord): JobSummary {
  const job = rec.job;
  const current = job.steps.find((s) => s.state.state !== "done" && s.state.state !== "skipped");
  const summary: JobSummary = {
    id: job.id,
    kind: job.spec.kind,
    title: job.spec.title,
    state: job.state,
    targets: job.spec.targets.map((t) => ({ ...t })),
    created: job.created,
    step_count: job.steps.length,
    steps_done: job.steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length,
    cancel_requested: !!job.cancel_requested,
    revision: job.revision ?? db.revision,
  };
  if (job.spec.group) summary.group = job.spec.group;
  if (job.finished) summary.finished = job.finished;
  if (job.runner !== undefined && job.runner !== null) summary.runner = job.runner;
  if (current) {
    summary.current_step = current.index;
    summary.current_step_state = current.state.state;
  }
  const manual = job.steps.filter((s) => s.state.state === "waiting_for_manual").map((s) => s.index);
  if (manual.length > 0) summary.manual_steps = manual;
  if (job.error) summary.error = job.error;
  return summary;
}

// ---------------------------------------------------------------------------------
// Changes by a person

/** The note of a completion must fit `MAX_NOTE_BYTES` bytes (`jobs.note.too_long`, 400). */
function checkNote(note: string | null): void {
  if (note !== null && new TextEncoder().encode(note).length > MAX_NOTE_BYTES) {
    throw new Problem("jobs.note.too_long", {
      status: 400,
      detail: `a note has at most ${MAX_NOTE_BYTES} bytes`,
      params: { max: String(MAX_NOTE_BYTES) },
    });
  }
}

/**
 * Completes a manual step (or a manual undo task of a job that rolls back) as the signed-in
 * user: the job goes on, a queued job of the group starts when a slot frees up, the change
 * is announced on the `jobs` topic and audited. Fails with `jobs.not_found`,
 * `jobs.step.not_found` (404), `jobs.invalid_transition` (409) or `jobs.note.too_long`.
 */
export function completeJobStep(id: string, index: number, note: string | null): MockJobRecord {
  checkNote(note);
  const rec = requireJob(id);
  const now = Date.now();
  completeStep(rec, { now, by: principalNow() }, index, note);
  const started = releaseSlot(rec, now);
  commitJobs([rec, ...started]);
  const context: Record<string, string> = { step: String(index) };
  if (note) context.note = note;
  appendAudit({ action: "jobs.step.complete", objects: [ref(rec)], context });
  return rec;
}

/**
 * Cancels a job as the signed-in user. A queued job is cancelled at once; a running or
 * waiting one rolls back (manual undo tasks keep it `rolling_back` until a person completes
 * them) and ends `cancelled`. Fails with `jobs.not_found` (404) or `jobs.invalid_transition`
 * (409) for a job that is rolling back or finished.
 */
export function cancelJob(id: string): MockJobRecord {
  const rec = requireJob(id);
  const now = Date.now();
  const queued = rec.job.state === "queued";
  cancelRecord(rec, { now, by: principalNow() });
  const started = releaseSlot(rec, now);
  commitJobs([rec, ...started]);
  appendAudit({
    action: queued ? "jobs.job.cancel" : "jobs.job.cancel_request",
    objects: [ref(rec)],
    context: { kind: rec.job.spec.kind },
  });
  return rec;
}

// ---------------------------------------------------------------------------------
// The ticker

function importInput(): MockJobInput {
  return {
    kind: "import.apply",
    title: "jobs.title.import_apply",
    targets: [{ kind: "import", id: randomId() }],
    timeoutSecs: 7200,
    preview: false,
    steps: [
      { kind: "import.parse", automatic: true, slow: true },
      { kind: "import.plan", automatic: true, slow: true },
      { kind: "import.apply_chunk", automatic: true, slow: true },
    ],
  };
}

/** Drops the oldest finished jobs beyond `KEEP_JOBS`; returns what it dropped. */
function prune(): ObjectRef[] {
  const dropped: ObjectRef[] = [];
  while (jobStore.jobs.length > KEEP_JOBS) {
    const finished = jobStore.jobs.filter((r) => isTerminal(r.job.state));
    const oldest = finished.reduce<MockJobRecord | undefined>(
      (best, r) => (!best || Date.parse(r.job.created.at) < Date.parse(best.job.created.at) ? r : best),
      undefined,
    );
    if (!oldest) break;
    jobStore.jobs.splice(jobStore.jobs.indexOf(oldest), 1);
    dropped.push(ref(oldest));
  }
  return dropped;
}

/**
 * One step of the job ticker: a job whose deadline passed rolls back, the running import
 * advances by one step (or a new import starts when none runs), and the list is trimmed.
 * Records one `jobs` event and returns it.
 */
export function advanceMockJobs(): MockEvent {
  const now = Date.now();
  const engine: Ctx = { now, by: SYSTEM_JOBS };
  const touched = new Set<MockJobRecord>();

  for (const rec of [...jobStore.jobs]) {
    if (!expireRecord(rec, engine)) continue;
    touched.add(rec);
    for (const next of releaseSlot(rec, now)) touched.add(next);
    appendAudit({
      action: "jobs.job.roll_back",
      objects: [ref(rec)],
      context: { kind: rec.job.spec.kind, error: rec.job.error?.code ?? "" },
      outcome: { kind: "failed", code: rec.job.error?.code ?? "jobs.timeout" },
      principal: SYSTEM_JOBS,
    });
  }

  const running = jobStore.jobs.find((r) => r.job.spec.kind === "import.apply" && r.job.state === "running");
  if (running) {
    tickRecord(running, engine);
    touched.add(running);
    for (const next of releaseSlot(running, now)) touched.add(next);
  } else {
    const rec = submit(importInput(), { now, by: SYSTEM_IMPORT });
    jobStore.jobs.unshift(rec);
    startRecord(rec, engine);
    touched.add(rec);
  }

  const dropped = prune();
  const alive = [...touched].filter((r) => jobStore.jobs.includes(r));
  return commitJobs(alive, dropped);
}

// ---------------------------------------------------------------------------------
// Seeds

function seedUser(name: "alex" | "sam"): Principal {
  return name === "alex"
    ? { kind: "user", id: MOCK_USER_IDS.alex, session: "0190d1c2-0000-7000-8000-0000000e0001", strength: "passkey" }
    : { kind: "user", id: MOCK_USER_IDS.sam, session: "0190d1c2-0000-7000-8000-0000000e0002", strength: "password" };
}

function seedJobs(): void {
  const now = Date.now();
  const alex = seedUser("alex");
  const sam = seedUser("sam");
  const at = (minutesAgo: number, by: Principal): Ctx => ({ now: now - minutesAgo * MINUTE, by });
  const records: MockJobRecord[] = [];

  // A move job that waits for a person to reserve the address in the DHCP server.
  const waiting = submit(
    moveJobInput({
      host: { kind: "host", id: MOCK_HOST_IDS.thermostat1 },
      name: "thermostat-1",
      fqdn: "thermostat-1.example.test",
      mac: "00:00:5e:00:53:29",
      ip: "198.51.100.41",
      oldIp: "192.0.2.41",
      group: MOCK_MOVE_GROUP,
      groupLimit: 2,
    }),
    at(62, alex),
    { id: MOCK_JOB_IDS.moveWaiting },
  );
  startRecord(waiting, at(60, SYSTEM_JOBS));
  records.push(waiting);

  // A second move job of the same group that has not been claimed yet.
  records.push(
    submit(
      moveJobInput({
        host: { kind: "host", id: MOCK_HOST_IDS.plugKitchen },
        name: "plug-kitchen",
        fqdn: "plug-kitchen.example.test",
        mac: "00:00:5e:00:53:2a",
        ip: "198.51.100.42",
        oldIp: "192.0.2.42",
        group: MOCK_MOVE_GROUP,
        groupLimit: 2,
      }),
      at(48, alex),
      { id: MOCK_JOB_IDS.moveQueued },
    ),
  );

  // An import that has parsed and planned and now applies its chunks.
  const running = submit(importInput(), at(8, sam), { id: MOCK_JOB_IDS.importRunning });
  startRecord(running, at(7, SYSTEM_JOBS));
  tickRecord(running, at(5, SYSTEM_JOBS));
  tickRecord(running, at(3, SYSTEM_JOBS));
  records.push(running);

  // An inline apply that succeeded.
  records.push(
    inlineRecord(
      { kind: "ipam.apply", title: "jobs.title.ipam_apply", targets: [{ kind: "host", id: MOCK_HOST_IDS.nas }] },
      at(15, alex),
      MOCK_JOB_IDS.applySucceeded,
    ),
  );

  // A move job whose layer 2 step failed. Its manual steps have no undo task, so the rollback
  // undid the steps at once, without waiting for a person.
  const l2Error: CodedError = {
    code: "jobs.step.failed",
    status: 502,
    title: "Step failed",
    detail: "No ARP or lease from 00:00:5e:00:53:2b within 5:00.",
  };
  const failed = submit(
    moveJobInput({
      host: { kind: "host", id: MOCK_HOST_IDS.camDoor },
      name: "cam-door",
      fqdn: "cam-door.example.test",
      mac: "00:00:5e:00:53:2b",
      ip: "198.51.100.43",
      oldIp: "192.0.2.43",
      group: MOCK_MOVE_GROUP,
      groupLimit: 2,
      l2FailsWith: l2Error,
    }),
    at(26 * 60, alex),
    { id: MOCK_JOB_IDS.moveRolledBack },
  );
  startRecord(failed, at(26 * 60 - 2, SYSTEM_JOBS));
  completeStep(failed, at(26 * 60 - 12, sam), 1, SEED_ROLLBACK_NOTES.dhcp);
  completeStep(failed, at(26 * 60 - 27, sam), 2, SEED_ROLLBACK_NOTES.dns);
  records.push(failed);

  // An apply that was cancelled before it started.
  const cancelled = submit(
    {
      kind: "ipam.apply",
      title: "jobs.title.ipam_apply",
      targets: [{ kind: "prefix", id: SEED_PREFIX_ID }],
      timeoutSecs: 60,
      preview: false,
      steps: [{ kind: "ipam.apply", automatic: true }],
    },
    at(180, sam),
    { id: MOCK_JOB_IDS.applyCancelled },
  );
  cancelRecord(cancelled, at(179, alex));
  records.push(cancelled);

  for (const rec of records) rec.job.revision = db.revision;
  records.sort((a, b) => Date.parse(b.job.created.at) - Date.parse(a.job.created.at));
  jobStore.jobs = records;
}

function reseed(): void {
  const setup = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  jobStore.jobs = [];
  if (!setup) seedJobs();
}

onMockReset(reseed);
reseed();
