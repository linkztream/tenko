// Jobs of the mock API: list, detail, cancel and manual-step completion (IPAM-17). The
// answers and error codes follow `crates/tenko-api/src/routes/jobs.rs`.
import type { HttpHandler } from "msw";
import type { JobDetail, JobState, ObjectKind } from "../types";
import { JOB_STATES } from "../types";
import { OBJECT_KINDS } from "./audit-store";
import { requireSession } from "./auth";
import { db } from "./db";
import { cancelJob, completeJobStep, findJob, jobStore, summarizeJob } from "./job-store";
import { Problem, Reply, fail, fieldError, ok } from "./reply";
import { paginate, route } from "./route";
import { isUuid } from "./util";

// ---------------------------------------------------------------------------------
// Query values (shared with the audit routes)

/** `sys.invalid_query` (400) naming the offending query parameter. */
export function invalidQuery(parameter: string, reason: string): never {
  throw new Problem("sys.invalid_query", {
    status: 400,
    detail: `query parameter \`${parameter}\`: ${reason}`,
    params: { parameter },
    errors: [fieldError(parameter, "sys.invalid_query")],
  });
}

/** Refuses a query parameter the endpoint does not know. */
export function onlyParams(url: URL, allowed: readonly string[]): void {
  for (const name of url.searchParams.keys()) {
    if (!allowed.includes(name)) invalidQuery(name, "unknown parameter");
  }
}

/** The one value of a parameter that may appear once; null when absent. */
export function singleParam(url: URL, name: string): string | null {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) return invalidQuery(name, "the parameter is repeated");
  return values[0] ?? null;
}

/** `at_least` is a store revision; the mock is always at least that far, so it only checks the value. */
export function checkAtLeast(url: URL): void {
  const value = singleParam(url, "at_least");
  if (value !== null && !/^\d+$/.test(value)) invalidQuery("at_least", "expected a store revision");
}

/** The largest page, like the server. */
const MAX_LIMIT = 1000;

/** `limit` is a whole number from 1 to 1,000 (the server refuses anything else). */
export function checkLimit(url: URL): void {
  const value = singleParam(url, "limit");
  if (value === null) return;
  if (!/^\d+$/.test(value) || Number(value) < 1) invalidQuery("limit", "must be at least 1");
  if (Number(value) > MAX_LIMIT) invalidQuery("limit", `must be at most ${MAX_LIMIT}`);
}

const ECHO_LIMIT = 128;

/** `jobs.query.invalid` (400): a value only the jobs endpoints understand is malformed. */
function queryValue(param: string, value: string, reason: string): never {
  const echoed = value.slice(0, ECHO_LIMIT);
  throw new Problem("jobs.query.invalid", {
    status: 400,
    detail: `invalid parameter \`${param}\` with value \`${echoed}\`: ${reason}`,
    params: { param, value: echoed },
  });
}

/** The values of a list parameter: repeated or comma-separated, blank ones ignored. */
function listParam(url: URL, name: string): string[] {
  return url.searchParams
    .getAll(name)
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value !== "");
}

function parseState(name: string): JobState {
  if (!(JOB_STATES as readonly string[]).includes(name)) return queryValue("state", name, "not a job state");
  return name as JobState;
}

function parseKind(name: string): string {
  if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(name) || name.length > 128) {
    return queryValue("kind", name, "not a job kind");
  }
  return name;
}

/** `kind/uuid`, the written form of an object reference. */
function parseTarget(raw: string): { kind: ObjectKind; id: string } {
  const slash = raw.indexOf("/");
  if (slash < 0) return queryValue("target", raw, "expected kind/uuid");
  const kind = raw.slice(0, slash);
  const id = raw.slice(slash + 1);
  if (!(OBJECT_KINDS as readonly string[]).includes(kind)) return queryValue("target", raw, "not an object kind");
  if (!isUuid(id)) return queryValue("target", raw, "not a UUID");
  return { kind: kind as ObjectKind, id: id.toLowerCase() };
}

/** The `{id}` path segment: a UUID (`jobs.query.invalid` otherwise). */
function parseJobId(raw: string): string {
  if (!isUuid(raw)) return queryValue("id", raw, "not a job identifier (UUID)");
  return raw.toLowerCase();
}

/** The `{index}` path segment: a whole number from 0 to 65535. */
function parseIndex(raw: string): number {
  const index = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(index) || index > 65535) {
    return queryValue("index", raw, "not a step index (a whole number from 0 to 65535)");
  }
  return index;
}

/** Cancelling and completing steps needs the `execute` right on jobs: admin or operator. */
function requireExecute(roles: readonly string[]): void {
  if (!roles.includes("admin") && !roles.includes("operator")) {
    fail("auth.forbidden", { detail: "this needs the admin or operator role" });
  }
}

// ---------------------------------------------------------------------------------
// Routes

const LIST_PARAMS = ["state", "kind", "target", "limit", "cursor", "at_least"];

const listJobs = route("get", "/api/v1/jobs", (ctx) => {
  requireSession();
  onlyParams(ctx.url, LIST_PARAMS);
  checkLimit(ctx.url);
  checkAtLeast(ctx.url);
  const states = listParam(ctx.url, "state").map(parseState);
  const kinds = listParam(ctx.url, "kind").map(parseKind);
  const rawTarget = singleParam(ctx.url, "target");
  const target = rawTarget === null ? null : parseTarget(rawTarget);
  // Newest first; jobs created in the same millisecond keep the order of the store.
  const rows = jobStore.jobs
    .filter(
      (rec) =>
        (states.length === 0 || states.includes(rec.job.state)) &&
        (kinds.length === 0 || kinds.includes(rec.job.spec.kind)) &&
        (target === null || rec.job.spec.targets.some((t) => t.kind === target.kind && t.id === target.id)),
    )
    .sort((a, b) => Date.parse(b.job.created.at) - Date.parse(a.job.created.at))
    .map(summarizeJob);
  return ok(paginate(rows, ctx.url, db.revision));
});

const getJob = route("get", "/api/v1/jobs/{id}", (ctx) => {
  requireSession();
  const id = parseJobId(ctx.params.id);
  onlyParams(ctx.url, ["at_least"]);
  checkAtLeast(ctx.url);
  const rec = findJob(id);
  if (!rec) {
    throw new Problem("jobs.not_found", { status: 404, detail: `job ${id} not found`, params: { job: id } });
  }
  const detail: JobDetail = { job: rec.job, transitions: rec.transitions, revision: db.revision };
  if (rec.preview) detail.preview = rec.preview;
  return ok(detail);
});

const cancel = route("post", "/api/v1/jobs/{id}/cancel", (ctx) => {
  const { user } = requireSession();
  const id = parseJobId(ctx.params.id);
  requireExecute(user.roles);
  return new Reply(202, summarizeJob(cancelJob(id)));
});

/** The note of the body: absent, null or a text; any other member or type is a bad request. */
function parseNote(body: Record<string, unknown>): string | null {
  for (const key of Object.keys(body)) {
    if (key !== "note") fail("sys.invalid_request", { detail: `the request body is not valid: unknown field \`${key}\`` });
  }
  const note = body.note;
  if (note === undefined || note === null) return null;
  if (typeof note !== "string") {
    return fail("sys.invalid_request", { detail: "the request body is not valid: `note` must be a text" });
  }
  return note;
}

const completeStep = route("post", "/api/v1/jobs/{id}/steps/{index}/complete", async (ctx) => {
  const { user } = requireSession();
  const id = parseJobId(ctx.params.id);
  const index = parseIndex(ctx.params.index);
  requireExecute(user.roles);
  const note = parseNote(await ctx.optionalBody());
  return ok(summarizeJob(completeJobStep(id, index, note)));
});

export const jobRoutes: HttpHandler[] = [listJobs, getJob, cancel, completeStep];
