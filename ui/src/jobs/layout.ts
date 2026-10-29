// The layout of the jobs list (docs/plans/ui-plan.md section 5.4), kept apart from the view so the
// rules are tested without a grid: the jobs that run or wait lead, the ones that wait for a person
// first, and are never grouped by day; finished jobs follow, grouped by the local day they
// finished on (Today, Yesterday, Earlier). Who started the jobs is said once when every job
// shares the starter (principle 7), and the number of jobs waiting for a person is the one of the
// findings store, the number of the rail badge.
import type { JobSummary, Principal } from "../api/types";
import { sharedValue } from "../grid/groups";
import { areaCounts, type FindingCounts } from "../shell/findings";
import { isFinal, needsPerson } from "./model";

// ---------------------------------------------------------------------------------
// The jobs that lead

/** The jobs that are not over, split into those that wait for a person and the others; order kept. */
export function leadRows(rows: readonly JobSummary[]): { needs: JobSummary[]; active: JobSummary[] } {
  const needs: JobSummary[] = [];
  const active: JobSummary[] = [];
  for (const job of rows) {
    if (isFinal(job.state)) continue;
    (needsPerson(job) ? needs : active).push(job);
  }
  return { needs, active };
}

// ---------------------------------------------------------------------------------
// Days

export type Day = "today" | "yesterday" | "earlier";
export const DAYS: readonly Day[] = ["today", "yesterday", "earlier"];
/** Rows a day shows until the person asks for the rest. */
export const DAY_ROWS = 10;

/** Local midnight at the start of the day of `at` (milliseconds). */
export function startOfDay(at: number): number {
  const d = new Date(at);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** Local midnight at the start of the day before the one that starts at `midnight`; DST-safe. */
export function dayBefore(midnight: number): number {
  const d = new Date(midnight);
  d.setDate(d.getDate() - 1);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * The day group of a moment, against the local midnight that starts today: from that midnight on
 * (a clock a little ahead included) Today, from the midnight before Yesterday, else Earlier.
 */
export function dayOf(at: number, today: number): Day {
  if (at >= today) return "today";
  return at >= dayBefore(today) ? "yesterday" : "earlier";
}

/** When a finished job finished; its submission when the server gave no end. */
export function finishedAt(job: Pick<JobSummary, "finished" | "created">): number {
  return Date.parse(job.finished ?? job.created.at);
}

/**
 * How long a finished job took, in seconds, from its submission to its end (the list carries no
 * start time); undefined while it runs or when the times do not add up.
 */
export function durationSeconds(job: Pick<JobSummary, "finished" | "created">): number | undefined {
  if (!job.finished) return undefined;
  const seconds = (Date.parse(job.finished) - Date.parse(job.created.at)) / 1000;
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

/** What the jobs of one day ended as, for the note of its group row. */
export type DayOutcome = "done" | "failed" | "mixed" | "other";

export interface DayBucket {
  day: Day;
  /** The jobs of the day, the latest to finish first. */
  rows: JobSummary[];
  /** Jobs that failed or were rolled back. */
  failed: number;
  outcome: DayOutcome;
}

function outcomeOf(rows: readonly JobSummary[], failed: number): DayOutcome {
  if (rows.every((job) => job.state === "succeeded")) return "done";
  if (failed === rows.length) return "failed";
  return failed > 0 ? "mixed" : "other";
}

/** The finished jobs of `rows` by day, against the midnight that starts today; empty days left out. */
export function dayBuckets(rows: readonly JobSummary[], today: number): DayBucket[] {
  const byDay = new Map<Day, JobSummary[]>(DAYS.map((day) => [day, []]));
  for (const job of rows) {
    if (!isFinal(job.state)) continue;
    byDay.get(dayOf(finishedAt(job), today))?.push(job);
  }
  const out: DayBucket[] = [];
  for (const day of DAYS) {
    const list = byDay.get(day) ?? [];
    if (list.length === 0) continue;
    list.sort((a, b) => finishedAt(b) - finishedAt(a));
    const failed = list.filter((job) => job.state === "failed" || job.state === "rolled_back").length;
    out.push({ day, rows: list, failed, outcome: outcomeOf(list, failed) });
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Who started the jobs

/** One principal as a comparable key. */
export function principalKey(p: Principal): string {
  switch (p.kind) {
    case "user":
      return `user:${p.id}`;
    case "token":
      return `token:${p.id}`;
    case "system":
      return `system:${p.component}`;
    case "node":
      return `node:${String(p.id)}`;
  }
}

/** The one principal who started every listed job, or undefined when two differ or nothing is listed. */
export function sharedStarter(rows: readonly JobSummary[]): Principal | undefined {
  const key = sharedValue(rows, (job) => principalKey(job.created.by));
  return key === undefined ? undefined : rows[0]?.created.by;
}

// ---------------------------------------------------------------------------------
// The waiting count

/**
 * The jobs that wait for a person, from the findings store: the number of the rail's Jobs badge
 * (act and review of the jobs area), or undefined while the store has no counts.
 */
export function waitingCount(counts: FindingCounts | null): number | undefined {
  if (!counts) return undefined;
  const level = areaCounts(counts, "jobs");
  return level.act + level.review;
}
