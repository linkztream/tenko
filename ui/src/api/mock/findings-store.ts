// The findings counts of the mock API (docs/reconciliation.md section 12): what `GET
// /api/v1/findings/counts` answers, derived from the mock state on every read so that a
// decided proposal, a completed manual step or a prefix filling up reaches the counts at once.
//
// What is derived: every open proposal is a finding of the area `discovery` (source `proposal`):
// a conflict is to act on, any other kind is to review, never information. Every job in the state
// `waiting` that has a manual step waiting for a person is a finding of the area `jobs` (source
// `job`) to act on. Every prefix whose utilization alarm is at `critical` is to act on, at
// `warning` to review: area `ipam`, source `alarm`.
//
// What is not: health conditions, the rows of the reconciliation view and scan artifacts. A test
// adds findings of any area and severity with `setMockFindingsExtra`; they count as `health`.
// Simplification: a job that rolls back and waits for an undo task is not counted.
import type { components } from "../generated/schema";
import { db, onMockReset } from "./db";
import { ipamState } from "./ipam/api";
import { jobStore } from "./job-store";
import { reconcileState } from "./reconcile-store";

type S = components["schemas"];
export type FindingCounts = S["FindingCounts"];
export type AreaCounts = S["AreaCounts"];
export type LevelCounts = S["LevelCounts"];
export type FindingArea = keyof AreaCounts;

/** Every area, in the order of the document. */
export const FINDING_AREAS: readonly FindingArea[] = ["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"];

const SEVERITIES = ["act", "review", "info"] as const;

type Extra = Partial<Record<FindingArea, Partial<LevelCounts>>>;

let extra: Extra = {};

/**
 * Adds counts per area and severity to the derived ones, as findings of the source `health`.
 * Replaces the earlier extra; an empty object clears it. A reset of the mock clears it too.
 */
export function setMockFindingsExtra(next: Extra): void {
  extra = structuredClone(next);
}

onMockReset(() => {
  extra = {};
});

function zero(): LevelCounts {
  return { act: 0, review: 0, info: 0 };
}

/** The counts the mock's state stands for, with the revision it was read at. */
export function mockFindingCounts(): FindingCounts {
  const areas = Object.fromEntries(FINDING_AREAS.map((area) => [area, zero()])) as AreaCounts;
  const sources = { alarm: 0, health: 0, job: 0, proposal: 0, reconcile: 0 };

  for (const proposal of reconcileState().proposals.values()) {
    if (proposal.state !== "open") continue;
    areas.discovery[proposal.kind === "conflict" ? "act" : "review"] += 1;
    sources.proposal += 1;
  }

  for (const { job } of jobStore.jobs) {
    if (job.state !== "waiting") continue;
    if (!job.steps.some((step) => step.state.state === "waiting_for_manual")) continue;
    areas.jobs.act += 1;
    sources.job += 1;
  }

  for (const level of ipamState().levels.values()) {
    if (level === "normal") continue;
    areas.ipam[level === "critical" ? "act" : "review"] += 1;
    sources.alarm += 1;
  }

  for (const area of FINDING_AREAS) {
    for (const severity of SEVERITIES) {
      const n = extra[area]?.[severity] ?? 0;
      areas[area][severity] += n;
      sources.health += n;
    }
  }

  const total = zero();
  for (const area of FINDING_AREAS) for (const severity of SEVERITIES) total[severity] += areas[area][severity];
  return { areas, problems: total.act + total.review, revision: db.revision, sources, total };
}
