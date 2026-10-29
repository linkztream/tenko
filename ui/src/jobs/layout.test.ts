import { describe, expect, it } from "vitest";
import type { JobState, JobSummary, Principal } from "../api/types";
import { railBadge } from "../shell/railBadge";
import type { FindingCounts } from "../shell/findings";
import { AREAS } from "../shell/areas";
import { dayBefore, dayBuckets, dayOf, durationSeconds, leadRows, principalKey, sharedStarter, startOfDay, waitingCount } from "./layout";

const ALEX: Principal = { kind: "user", id: "0190d1c2-0000-7000-8000-00000000a001", session: "0190d1c2-0000-7000-8000-0000000e0001", strength: "passkey" };
const SAM: Principal = { kind: "user", id: "0190d1c2-0000-7000-8000-00000000a002", session: "0190d1c2-0000-7000-8000-0000000e0002", strength: "password" };

let next = 0;
function job(state: JobState, options: { finished?: Date; created?: Date; by?: Principal; manual?: number[] } = {}): JobSummary {
  next += 1;
  const created = options.created ?? options.finished ?? new Date(2026, 9, 29, 9, 0, 0);
  return {
    id: `0190d1c2-0000-7000-8000-${String(next).padStart(12, "0")}`,
    kind: "ipam.edit",
    title: "ipam.job.edit",
    state,
    created: { at: created.toISOString(), by: options.by ?? ALEX },
    finished: options.finished ? options.finished.toISOString() : null,
    cancel_requested: false,
    revision: 1,
    step_count: 1,
    steps_done: state === "succeeded" ? 1 : 0,
    targets: [],
    manual_steps: options.manual ?? [],
  };
}

describe("the day of a finished job", () => {
  // 29 October 2026, local time.
  const today = startOfDay(new Date(2026, 9, 29, 15, 30).getTime());

  it("starts the day at local midnight", () => {
    expect(new Date(today).getHours()).toBe(0);
    expect(new Date(today).getDate()).toBe(29);
    expect(new Date(dayBefore(today)).getDate()).toBe(28);
    expect(new Date(dayBefore(today)).getHours()).toBe(0);
  });

  it("puts midnight in today and a minute before it in yesterday", () => {
    expect(dayOf(new Date(2026, 9, 29, 0, 0, 0).getTime(), today)).toBe("today");
    expect(dayOf(new Date(2026, 9, 28, 23, 59, 0).getTime(), today)).toBe("yesterday");
    expect(dayOf(new Date(2026, 9, 28, 23, 59, 59, 999).getTime(), today)).toBe("yesterday");
    expect(dayOf(new Date(2026, 9, 28, 0, 0, 0).getTime(), today)).toBe("yesterday");
    expect(dayOf(new Date(2026, 9, 27, 23, 59, 59).getTime(), today)).toBe("earlier");
    // A clock a little ahead of this one is still today.
    expect(dayOf(new Date(2026, 9, 29, 16, 0).getTime(), today)).toBe("today");
  });

  it("keeps a job that finished at 23:59 yesterday in yesterday a minute after midnight", () => {
    const justAfter = startOfDay(new Date(2026, 9, 29, 0, 1).getTime());
    expect(dayOf(new Date(2026, 9, 28, 23, 59).getTime(), justAfter)).toBe("yesterday");
    expect(dayOf(new Date(2026, 9, 29, 0, 0, 30).getTime(), justAfter)).toBe("today");
  });

  it("follows the calendar over a change of daylight saving time", () => {
    // The last Sunday of October: a day of 25 hours in much of Europe.
    const monday = startOfDay(new Date(2026, 9, 26, 12).getTime());
    expect(new Date(dayBefore(monday)).getDate()).toBe(25);
    expect(dayOf(new Date(2026, 9, 25, 0, 30).getTime(), monday)).toBe("yesterday");
    expect(dayOf(new Date(2026, 9, 24, 23, 30).getTime(), monday)).toBe("earlier");
  });

  it("groups finished jobs by day, the latest first, and leaves the jobs that run out", () => {
    const rows = [
      job("succeeded", { finished: new Date(2026, 9, 29, 8, 0) }),
      job("succeeded", { finished: new Date(2026, 9, 29, 14, 0) }),
      job("failed", { finished: new Date(2026, 9, 28, 23, 59) }),
      job("succeeded", { finished: new Date(2026, 9, 28, 10, 0) }),
      job("cancelled", { finished: new Date(2026, 9, 20, 10, 0) }),
      job("running"),
    ];
    const buckets = dayBuckets(rows, today);
    expect(buckets.map((b) => b.day)).toEqual(["today", "yesterday", "earlier"]);
    expect(buckets[0]?.rows.map((r) => r.id)).toEqual([rows[1]?.id, rows[0]?.id]);
    expect(buckets.map((b) => b.outcome)).toEqual(["done", "mixed", "other"]);
    expect(buckets[1]?.failed).toBe(1);
    expect(dayBuckets([job("rolled_back", { finished: new Date(2026, 9, 29, 1, 0) })], today)[0]?.outcome).toBe("failed");
    expect(dayBuckets([job("running")], today)).toEqual([]);
  });

  it("measures a job from its submission to its end", () => {
    const done = job("succeeded", { created: new Date(2026, 9, 29, 9, 0, 0), finished: new Date(2026, 9, 29, 9, 2, 10) });
    expect(durationSeconds(done)).toBe(130);
    expect(durationSeconds(job("running"))).toBeUndefined();
    const skewed = job("succeeded", { created: new Date(2026, 9, 29, 9, 0, 1), finished: new Date(2026, 9, 29, 9, 0, 0) });
    expect(durationSeconds(skewed)).toBeUndefined();
  });
});

describe("the jobs that lead", () => {
  it("puts the jobs that wait for a person apart from the others, in the order of the list", () => {
    const rows = [job("running"), job("waiting", { manual: [1] }), job("queued"), job("waiting"), job("rolling_back", { manual: [2] }), job("succeeded")];
    const { needs, active } = leadRows(rows);
    expect(needs.map((r) => r.id)).toEqual([rows[1]?.id, rows[4]?.id]);
    expect(active.map((r) => r.id)).toEqual([rows[0]?.id, rows[2]?.id, rows[3]?.id]);
  });
});

describe("who started the jobs", () => {
  it("names the one starter of every job, and none as soon as there are two", () => {
    const mine = Array.from({ length: 200 }, () => job("succeeded", { finished: new Date(2026, 9, 29, 9, 0), by: ALEX }));
    expect(sharedStarter(mine)).toEqual(ALEX);
    expect(sharedStarter([...mine, job("succeeded", { by: SAM })])).toBeUndefined();
    expect(sharedStarter([])).toBeUndefined();
  });

  it("tells principals apart by kind and id, not by session", () => {
    expect(principalKey(ALEX)).toBe(principalKey({ ...ALEX, session: "0190d1c2-0000-7000-8000-0000000e0009" }));
    expect(principalKey(ALEX)).not.toBe(principalKey(SAM));
    expect(principalKey({ kind: "system", component: "reconciler" })).toBe("system:reconciler");
    expect(principalKey({ kind: "node", id: 3 })).toBe("node:3");
  });
});

describe("the waiting count", () => {
  const counts = (act: number, review: number): FindingCounts =>
    ({
      revision: 1,
      total: { act, review, info: 0 },
      areas: {
        ipam: { act: 0, review: 0, info: 0 },
        dns: { act: 0, review: 0, info: 0 },
        dhcp: { act: 0, review: 0, info: 0 },
        discovery: { act: 0, review: 0, info: 0 },
        topology: { act: 0, review: 0, info: 0 },
        jobs: { act, review, info: 0 },
        connectors: { act: 0, review: 0, info: 0 },
        nodes: { act: 0, review: 0, info: 0 },
        settings: { act: 0, review: 0, info: 0 },
      },
    }) as unknown as FindingCounts;

  it("is the number of the rail's Jobs badge", () => {
    const area = AREAS.find((a) => a.id === "jobs");
    if (!area) throw new Error("no jobs area");
    for (const [act, review] of [
      [1, 0],
      [3, 2],
      [0, 4],
    ] as const) {
      const badge = railBadge(area, counts(act, review), false);
      expect(badge?.kind).toBe("count");
      expect(waitingCount(counts(act, review))).toBe(badge?.kind === "count" ? badge.count : -1);
    }
    expect(waitingCount(counts(0, 0))).toBe(0);
    expect(railBadge(area, counts(0, 0), false)).toBeNull();
    expect(waitingCount(null)).toBeUndefined();
  });
});
