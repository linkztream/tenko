// The words of the jobs views, as pure functions over `t`, so a view never spells a state,
// a title or a task out itself and a language switch reaches all of them. The dashboard and
// the job panels reuse these.
//
// Messages that come from the server (job titles, step summaries, manual tasks, errors) are
// keys, because the server owns the jobs but not the language. A key this UI does not know yet
// is shown as it is, which is readable enough to report; it never breaks a page.
import { errorMessage, isApiError } from "../api/problem";
import type { CodedError, JobState, JobSummary, ManualTask, StepPreview, StepRecord, StepStateKind } from "../api/types";
import { t, tDynamic } from "../i18n";
import { manualOf } from "./model";

// ---------------------------------------------------------------------------------
// States

/** "Queued", "Running", "Waiting", "Rolling back", "Done", "Failed", "Rolled back", "Cancelled". */
export function jobStateWord(state: JobState): string {
  return t(`jobs.state.${state}`);
}

/**
 * The `.jstate` classes of design.css for a job state. A cancelled job looks like a queued one
 * (hollow ring) with its word struck through; a job that rolls back looks like a rolled back
 * one. The glyph and the word always come together, so color is never the only cue.
 */
export function jobStateClass(state: JobState): string {
  switch (state) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "waiting":
      return "waiting";
    case "succeeded":
      return "done";
    case "failed":
      return "failed";
    case "rolled_back":
    case "rolling_back":
      return "rolledback";
    case "cancelled":
      return "queued cancelled";
  }
}

/**
 * Whether a cancelled job was rolled back by its cancellation: a cancel that reaches a job whose
 * steps have run undoes them first, and the job still ends `cancelled` (a move then keeps the old
 * address and tags the host `move-failed`). A summary tells by its current step, the first step
 * that is not done, which the compensation leaves `compensated`; a full job by its steps.
 */
export function cancelRolledBack(
  job: Pick<JobSummary, "state" | "current_step_state"> | { state: JobState; steps: readonly StepRecord[] },
): boolean {
  if (job.state !== "cancelled") return false;
  if ("steps" in job) return job.steps.some((step) => step.state.state === "compensated");
  return job.current_step_state === "compensated";
}

/** The state of a job in words, with "Rolled back (cancelled)" for a cancel that undid steps. */
export function jobStateText(state: JobState, rollback?: "cancel"): string {
  return rollback === "cancel" && state === "cancelled" ? t("jobs.state.cancelled_rolled_back") : jobStateWord(state);
}

/** The state of one step in words. */
export function stepStateWord(state: StepStateKind): string {
  return t(`jobs.step_state.${state}`);
}

/** The `.jstate` classes for a step: the same glyphs as for jobs. */
export function stepStateClass(state: StepStateKind): string {
  switch (state) {
    case "pending":
    case "skipped":
      return "queued";
    case "running":
    case "compensating":
      return "running";
    case "waiting_for_observation":
    case "waiting_for_manual":
      return "waiting";
    case "done":
      return "done";
    case "failed":
    case "compensation_failed":
      return "failed";
    case "compensated":
      return "rolledback";
  }
}

// ---------------------------------------------------------------------------------
// Titles, steps and tasks

/** The translated title of a job (a `Job`, a `JobSummary` or a bare spec). */
export function jobTitle(job: { title: string } | { spec: { title: string } }): string {
  const key = "spec" in job ? job.spec.title : job.title;
  return tDynamic(key) ?? key;
}

/** A step kind as the tail of a message key: `dhcp.manual` is `dhcp_manual`. */
function snake(kind: string): string {
  return kind.replace(/\./g, "_");
}

/** The message key of a step kind's summary: `dhcp.manual` is `jobs.step.dhcp_manual`. */
export function stepKey(kind: string): string {
  return `jobs.step.${snake(kind)}`;
}

/**
 * The arguments each summary needs: only those the server always sends (a message that names
 * an argument which is missing cannot be formatted). A summary is only formatted when the step
 * carries them; otherwise the short name of the step kind stands in, never a raw message key.
 */
const SUMMARY_ARGS: Readonly<Record<string, readonly string[]>> = {
  // The steps of a move job as the server sends them: automatic steps by summary, manual steps by task.
  "ipam.move.step.intent": ["old_ip", "new_ip"],
  "ipam.move.step.cleanup": ["old_ip", "new_ip"],
  // The DHCP preparation (WP: moves and the lease): the client is marked as moving, then the job
  // waits for the renewal with the short lease. `next_activity` is an RFC 3339 time (see `messageValues`).
  "ipam.move.step.prepare": ["old_ip", "new_ip", "cidr"],
  "ipam.move.step.short_lease": ["old_ip", "new_ip", "cidr"],
  "ipam.move.task.short_lease": ["old_ip", "new_ip", "cidr", "mac", "short_secs", "next_activity"],
  "ipam.move.task.dhcp": ["new_ip", "cidr"],
  "ipam.move.task.dns": ["name", "new_ip"],
  "ipam.move.task.device": ["new_ip", "cidr"],
  "ipam.move.task.l2": ["cidr"],
  // The layer 2 change through the network controller (`ipam.move.controller`) and the tasks of a
  // person when the controller cannot make it (`ipam.move.l2`): the arguments the server always
  // sends for that case, on top of the address and network arguments every move step carries.
  "ipam.move.step.controller_port": ["port", "device", "after", "connector"],
  "ipam.move.step.controller_client": ["mac", "after", "connector"],
  "ipam.move.task.l2_vlan": ["vid"],
  "ipam.move.task.l2_port": ["connector", "port", "device", "profile", "vid"],
  "ipam.move.task.l2_client": ["connector", "mac", "network", "vid"],
  "ipam.move.task.l2_port_vlan": ["connector", "port", "device", "vid"],
  "ipam.move.task.l2_shared_port": ["port", "device", "vid", "count"],
  "ipam.move.task.l2_ssid": ["ssid", "device", "vid"],
  "ipam.move.task.l2_network": ["connector", "vid"],
  "ipam.move.task.l2_refused": ["rule", "vid"],
  "ipam.move.task.observe": ["new_ip", "cidr", "timeout_secs"],
  "ipam.move.task.generic": ["old_ip", "new_ip", "cidr"],
  // The steps of a VLAN provision job (WP2.7): automatic steps by summary, the manual one by task.
  "ipam.vlan.step.intent": ["vid", "name"],
  "ipam.vlan.step.controller": ["vid", "name"],
  "ipam.vlan.step.activate": ["vid"],
  "ipam.vlan.task.network": ["vid", "name"],
  // The kinds earlier versions of the mock used.
  "jobs.step.ipam_intent": ["host"],
  "jobs.step.dhcp_manual": ["host", "ip"],
  "jobs.step.device_manual": ["host", "ip"],
  "jobs.step.dns_manual": ["name", "new_ip"],
  "jobs.step.l2_move": ["host", "vlan"],
  "jobs.step.observe": ["host", "ip"],
  "jobs.step.cleanup": ["host"],
};

/** The arguments the message `key` needs, for the tests that keep the table and the messages in step. */
export function summaryArgs(key: string): readonly string[] {
  return SUMMARY_ARGS[key] ?? [];
}

/** The short name of a step kind ("Reserve in DHCP"), also the heading of its checklist group. */
export function stepName(kind: string): string {
  return tDynamic(`jobs.stepname.${snake(kind)}`) ?? kind;
}

/** The arguments the server sends as RFC 3339 times; the messages format them as dates and times. */
const TIME_ARGS: readonly string[] = ["next_activity"];

/**
 * The values of a message: the arguments as sent, with the times as dates. A time that does not
 * parse is left out, so the message counts as lacking it and the step kind stands in.
 */
function messageValues(args: Readonly<Record<string, string>> | undefined): Record<string, string | Date> | undefined {
  if (!args) return undefined;
  const out: Record<string, string | Date> = { ...args };
  for (const name of TIME_ARGS) {
    const value = args[name];
    if (value === undefined) continue;
    const at = new Date(value);
    if (Number.isNaN(at.getTime())) delete out[name];
    else out[name] = at;
  }
  return out;
}

/** Formats a summary key when the step carries its arguments, else names the step kind. */
function summaryFor(
  key: string,
  kind: string,
  args: Readonly<Record<string, string>> | undefined,
  last: string,
): string {
  const needed = SUMMARY_ARGS[key] ?? [];
  const values = messageValues(args);
  if (needed.every((name) => values?.[name] !== undefined)) {
    const text = tDynamic(key, values);
    if (text !== undefined) return text;
  }
  return tDynamic(`jobs.stepname.${snake(kind)}`) ?? last;
}

/** What a step does, in one line: `jobs.step.<kind>` with the arguments of the step. */
export function stepSummary(kind: string, args?: Readonly<Record<string, string>>): string {
  return summaryFor(stepKey(kind), kind, args, kind);
}

/**
 * What one step of a job does. The job preview names the summary and its arguments; without
 * one, the step kind gives the summary. A task that waits adds its arguments.
 */
export function describeStep(step: StepRecord, preview?: StepPreview): string {
  const args = { ...(manualOf(step)?.task.args ?? {}), ...(preview?.args ?? {}) };
  const key = preview?.summary ?? stepKey(step.kind);
  return summaryFor(key, step.kind, args, preview?.summary ?? step.kind);
}

/**
 * The text of a manual task. A task that waits during a rollback already carries its undo
 * text as the instruction; with `undo` a task that still has an undo text shows that instead.
 */
export function taskText(task: ManualTask, undo = false): string {
  const key = undo && task.undo ? task.undo : task.instruction;
  // The engine's generic undo text names the raw step kind; the words of the kind read better.
  if (key === "jobs.undo.step" && task.args?.kind && task.args.step !== undefined) {
    return t("jobs.undo.step_named", { step: task.args.step, name: stepName(task.args.kind) });
  }
  return tDynamic(key, messageValues(task.args)) ?? key;
}

// ---------------------------------------------------------------------------------
// Errors

/** Numeric strings become numbers so number and plural arguments format correctly. */
function messageArgs(params: Readonly<Record<string, string>> | undefined): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(params ?? {})) out[k] = /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v;
  return out;
}

/** `jobs.step.failed` is read from `jobs.error.step_failed`: the job codes have a home of their own. */
function jobErrorKey(code: string): string {
  return `jobs.error.${code.replace(/^jobs\./, "").replace(/\./g, "_")}`;
}

function translated(code: string, params: Readonly<Record<string, string>> | undefined): string | undefined {
  const args = messageArgs(params);
  return tDynamic(`errors.${code}`, args) ?? tDynamic(jobErrorKey(code), args);
}

/**
 * The words for an error stored on a job or a step: the translation of its code, else the
 * server's English detail, else its title.
 */
export function codedErrorText(error: CodedError): string {
  return translated(error.code, error.params) ?? (error.detail || error.title || t("errors.generic.unexpected"));
}

/**
 * Codes whose translation says everything: the server's detail of these is a fixed English
 * sentence that only repeats it.
 */
const SELF_EXPLAINING: ReadonlySet<string> = new Set([
  "jobs.cancelled",
  "jobs.timeout",
  "jobs.step.deadline_passed",
  "jobs.step.timeout",
  "jobs.step.interrupted",
]);

/**
 * The server's own explanation of an error, when it adds something to the translation: the
 * message a step failed with names the device or the address, which no translation can.
 */
export function codedErrorDetail(error: CodedError): string | undefined {
  if (SELF_EXPLAINING.has(error.code)) return undefined;
  const own = translated(error.code, error.params);
  return own !== undefined && error.detail && error.detail !== own ? error.detail : undefined;
}

/** The words for an error of an action (cancel, mark done): job codes first, then the shared ones. */
export function problemText(err: unknown): string {
  if (isApiError(err)) {
    const own = translated(err.code, err.params);
    if (own !== undefined) return own;
  }
  return errorMessage(err);
}
