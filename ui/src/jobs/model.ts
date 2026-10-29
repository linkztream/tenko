// Pure helpers of the jobs views: which jobs a filter chip shows, what a person can do with
// a job in its state, the order of the manual checklist, the longest note, and the pieces of
// a countdown. Nothing here touches the DOM, the network or the language packs, so the
// rules are tested on their own (model.test.ts).
import type { CodedError, JobState, JobSummary, ManualTask, StepRecord, StepState } from "../api/types";

/** What a step that waits for an observation carries: the condition and the deadline. */
export type ObservationData = Extract<StepState, { state: "waiting_for_observation" }>["data"];

/** Longest note of a completed step, in bytes (the server refuses more: `jobs.note.too_long`). */
export const MAX_NOTE_BYTES = 4096;

/** The size of a note as the server counts it: UTF-8 bytes, not characters. */
export function noteBytes(note: string): number {
  return new TextEncoder().encode(note).length;
}

// ---------------------------------------------------------------------------------
// States

/** Final states: the job does not change any more. */
export const FINAL_STATES: readonly JobState[] = ["succeeded", "failed", "rolled_back", "cancelled"];
/** Everything that is not final: the job still holds, or waits for, work. */
export const ACTIVE_STATES: readonly JobState[] = ["queued", "running", "waiting", "rolling_back"];

export function isFinal(state: JobState): boolean {
  return FINAL_STATES.includes(state);
}

/**
 * Whether Cancel is offered. A job that already rolls back cannot be cancelled (the server
 * answers `jobs.invalid_transition`), and a job whose cancellation is requested is on its way.
 */
export function canCancel(state: JobState, cancelRequested: boolean): boolean {
  return !cancelRequested && (state === "queued" || state === "running" || state === "waiting");
}

/** Whether the job waits for a person: a manual task or a manual undo task is open. */
export function needsPerson(job: Pick<JobSummary, "manual_steps">): boolean {
  return (job.manual_steps?.length ?? 0) > 0;
}

/** Share of the steps that are done, 0 to 100. */
export function progressPercent(done: number, total: number): number {
  if (!(total > 0)) return 0;
  return Math.min(100, Math.max(0, Math.round((done / total) * 100)));
}

// ---------------------------------------------------------------------------------
// The state chips of the list

/**
 * The chips of the list (docs/plans/ui-plan.md section 5.4). "Active and needs you" is the
 * default: the jobs that run or wait lead, the ones that wait for a person first, and the
 * finished jobs follow by day. "Failed or rolled back" and "Finished" show finished jobs only,
 * by day; "All" shows every job in the layout of the default.
 */
export type JobView = "active" | "failed" | "finished" | "all";
export const VIEWS: readonly JobView[] = ["active", "failed", "finished", "all"];

/** The view in the URL; `needs`, the chip the default took over, reads as the default. */
export function parseView(value: unknown): JobView {
  if (value === "needs") return "active";
  return typeof value === "string" && (VIEWS as readonly string[]).includes(value) ? (value as JobView) : "active";
}

/** Whether a view leads with the jobs that run or wait. */
export function leadsWithActive(view: JobView): boolean {
  return view === "active" || view === "all";
}

/** Whether a job is listed under a chip. */
export function matchesView(view: JobView, job: Pick<JobSummary, "state">): boolean {
  switch (view) {
    case "active":
    case "all":
      return true;
    case "failed":
      return job.state === "failed" || job.state === "rolled_back";
    case "finished":
      return isFinal(job.state);
  }
}

// ---------------------------------------------------------------------------------
// Groups

/**
 * A short form of a job group for headings. A move group is `ipam.move.` and the 32 hex digits
 * of an id; older ones were `move-<id>`. The words in front go and the first eight characters of
 * the id stay.
 */
export function groupLabel(group: string): string {
  return group.replace(/^([a-z][a-z0-9_]*[.-])+/, "").slice(0, 8);
}

/**
 * The step kinds of a move job in the order of the job, which is the order of the checklist
 * (IPAM-19, design decision 7): the mark that the client is moving, the intent, the DHCP
 * reservation, the DNS records, the device, the wait for the short lease, the layer 2 change,
 * the bounce of the port or the kick of the client (ADR 0028),
 * the observation and the cleanup.
 */
export const STEP_ORDER: readonly string[] = [
  "ipam.move.prepare",
  "ipam.move.intent",
  "ipam.move.dhcp",
  "ipam.move.dns",
  "ipam.move.device",
  "ipam.move.lease",
  "ipam.move.l2",
  "ipam.move.nudge",
  "ipam.move.observe",
  "ipam.move.cleanup",
];

/**
 * Step kinds that stand in a place of the order above: the kinds earlier versions of the mock used,
 * and the layer 2 change through the network controller (`ipam.move.controller`, preview kind
 * `l2.controller`), which takes the place of the manual layer 2 step when the controller can do it.
 */
const KIND_ALIASES: Readonly<Record<string, string>> = {
  "dhcp.prepare": "ipam.move.prepare",
  "dhcp.short_lease": "ipam.move.lease",
  "l2.nudge": "ipam.move.nudge",
  "ipam.intent": "ipam.move.intent",
  "dhcp.manual": "ipam.move.dhcp",
  "dns.manual": "ipam.move.dns",
  "device.manual": "ipam.move.device",
  "l2.move": "ipam.move.l2",
  "l2.controller": "ipam.move.l2",
  "ipam.move.controller": "ipam.move.l2",
  observe: "ipam.move.observe",
  cleanup: "ipam.move.cleanup",
};

/** Position of a step kind in the checklist; kinds this UI does not know come last. */
export function kindRank(kind: string): number {
  const i = STEP_ORDER.indexOf(KIND_ALIASES[kind] ?? kind);
  return i < 0 ? STEP_ORDER.length : i;
}

// ---------------------------------------------------------------------------------
// What a step carries

/** The task and deadline of a step that waits for a person. */
export function manualOf(step: StepRecord): { task: ManualTask; deadline: string | null } | undefined {
  const s = step.state;
  return s.state === "waiting_for_manual" ? { task: s.data.task, deadline: s.data.deadline ?? null } : undefined;
}

/** What a step that waits for an observation waits for, and until when. */
export function observationOf(step: StepRecord): ObservationData | undefined {
  const s = step.state;
  return s.state === "waiting_for_observation" ? s.data : undefined;
}

/** The error of a step that failed or could not be undone. */
export function stepErrorOf(step: StepRecord): CodedError | undefined {
  const s = step.state;
  return s.state === "failed" || s.state === "compensation_failed" ? s.data.error : undefined;
}

// ---------------------------------------------------------------------------------
// Countdown

export type CountdownUnit = "d" | "h" | "min" | "s";
export interface CountdownPart {
  unit: CountdownUnit;
  value: number;
}

const UNITS: readonly (readonly [CountdownUnit, number])[] = [
  ["d", 86_400],
  ["h", 3_600],
  ["min", 60],
  ["s", 1],
];

/**
 * The two largest units of a time span that are not zero: 39,560 s is 10 h 59 min, 75 s is
 * 1 min 15 s, 20 s is 20 s. Seconds are dropped while there are hours, so the text changes
 * once a minute and never flickers.
 */
export function countdownParts(totalSeconds: number): CountdownPart[] {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  for (let i = 0; i < UNITS.length; i += 1) {
    const [unit, size] = UNITS[i] as readonly [CountdownUnit, number];
    if (seconds < size && i < UNITS.length - 1) continue;
    const first: CountdownPart = { unit, value: Math.floor(seconds / size) };
    const next = UNITS[i + 1];
    if (!next) return [first];
    const second = Math.floor((seconds % size) / next[1]);
    return second > 0 ? [first, { unit: next[0], value: second }] : [first];
  }
  return [{ unit: "s", value: 0 }];
}
