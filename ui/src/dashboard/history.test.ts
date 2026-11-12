// The tiles' history (OPS-20): the client's rules for the buckets on the golden example, and the
// chart's geometry over stepped frames (docs/plans/dashboard-history-plan.md, section 6, "How the
// motion was checked"), on the test data of historyTestData.ts.
import { describe, expect, it } from "vitest";
import type { components } from "../api/generated/schema";
import { axisX, bucketsAt, forEachGridLine, heldOf, place, REACH, scaleTop, TAU, withClosed, type Bucket, type HeldHistory, type HistoryFrame } from "./history";
import { cannedMetricsHistory } from "../api/mock/sse";
import { testHistory } from "./historyTestData";
import goldenMetrics from "../../../docs/api/examples/metrics-stream.jsonl?raw";

type S = components["schemas"];
const GOLDEN = goldenMetrics
  .split("\n")
  .filter((line) => line.length > 0)
  .map((line) => JSON.parse(line) as { history?: HistoryFrame; metrics?: S["MetricsSnapshot"] });
const golden = () => heldOf(GOLDEN[0]!.history!);
const closed = () => structuredClone(GOLDEN[1]!.metrics!.closed!);
const moved = (list: S["MetricsClosed"][], seconds: number) => {
  for (const tier of list[0]!.tiers) tier.start = new Date(Date.parse(tier.start) + seconds * 1000).toISOString();
  return list;
};

/** The plot of a tile of 283 px: 249 px wide. */
const W = 249;
const T0 = Date.parse("2026-11-12T09:58:00Z") / 1000;

describe("the client's history", () => {
  it("holds the golden history by figure, finest tier first, with the controllers' starts", () => {
    const held = golden();
    expect([...held.figures.keys()]).toEqual(["dns-queries", "dns-cache", "host-disk"]);
    const seconds = held.figures.get("dns-queries")!.tiers[0]!;
    expect([seconds.step, seconds.ring, seconds.first]).toEqual([1, 71, Date.parse("2026-10-09T11:59:57Z") / 1000]);
    expect(held.controllers.map((c) => [c.node, c.started !== null, c.unsupported])).toEqual([
      [1, true, false],
      [2, true, false],
      [3, false, true],
    ]);
  });

  it("appends closed buckets by their start, a later copy replacing the open one", () => {
    const held = golden();
    const next = withClosed(held, closed())!;
    const tier = next.figures.get("dns-queries")!.tiers[0]!;
    expect(tier.covered).toEqual([1000, 0, 1000, 1000, 1000, 1000]);
    expect(tier.mean.slice(-2)).toEqual([756, 750]);
    // A figure without a closed bucket is the same object: its chart keeps its buckets.
    expect(next.figures.get("dns-cache")).toBe(held.figures.get("dns-cache"));
  });

  it("asks for a fresh history on a hole, an unknown figure or an unknown tier", () => {
    // The newest closed bucket two seconds on still follows the newest held; three seconds on leaves a hole.
    expect(withClosed(golden(), moved(closed(), 2))).not.toBeNull();
    expect(withClosed(golden(), moved(closed(), 3))).toBeNull();
    const figure = closed();
    figure[0]!.figure = "dhcp-leases";
    expect(withClosed(golden(), figure)).toBeNull();
    const tier = closed();
    tier[0]!.tiers[0]!.step_ms = 60_000;
    expect(withClosed(golden(), tier)).toBeNull();
  });

  it("drops the oldest buckets beyond the ring", () => {
    let held: HeldHistory | null = golden();
    for (let s = 0; s < 80; s++) held = withClosed(held!, moved(closed(), s));
    const tier = held!.figures.get("dns-queries")!.tiers[0]!;
    expect(tier.covered).toHaveLength(71);
    expect(tier.first + 70).toBe(Date.parse("2026-10-09T12:00:02Z") / 1000 + 79);
  });
});

/** The drawn buckets of a figure at `at` on the plot. */
function frame(history: HeldHistory, at: number, name: "dns-queries" | "dns-cache" = "dns-queries"): Bucket[] {
  const buckets = bucketsAt(history.figures.get(name), at);
  place(buckets, at, W);
  return buckets;
}

describe("the axis", () => {
  it("runs from the reach at the left to now at the right, evenly near now and compressed toward the past", () => {
    expect(axisX(0, W)).toBe(W);
    expect(axisX(REACH, W)).toBeCloseTo(0, 9);
    // About 1.3 px a second at the right end, where asinh is a straight line.
    const pace = axisX(0, W) - axisX(1, W);
    expect(pace).toBeCloseTo(1.28, 2);
    expect((axisX(10, W) - axisX(11, W)) / pace).toBeGreaterThan(0.85);
    // The last minute takes about the right fifth, the last hour the right three fifths.
    expect(1 - axisX(60, W) / W).toBeGreaterThan(0.17);
    expect(1 - axisX(60, W) / W).toBeLessThan(0.23);
    expect(1 - axisX(3600, W) / W).toBeCloseTo(0.6, 1);
    expect(TAU).toBe(20);
  });

  it("draws no bucket wider than 5 px on a tile of 283 px (a ratio's 5-second buckets 7 px), at any moment", () => {
    const at = T0 + 45;
    const held = heldOf(testHistory({ at, figures: ["dns-queries", "dns-cache"] }));
    for (let t = T0; t < T0 + 40; t += 0.7) {
      for (const b of frame(held, t)) expect(b.x1 - b.x0, `${b.step} s at ${b.start}`).toBeLessThanOrEqual(5);
      for (const b of frame(held, t, "dns-cache")) expect(b.x1 - b.x0).toBeLessThanOrEqual(b.step === 5 ? 7 : 5);
    }
  });

  it("covers the reach once: every drawn bucket whole and next to its neighbors, oldest first", () => {
    const at = T0 + 0.4;
    const buckets = frame(heldOf(testHistory({ at })), at);
    expect(buckets.length).toBeGreaterThan(220);
    expect(buckets.length).toBeLessThan(290);
    for (let i = 1; i < buckets.length; i++) expect(buckets[i]!.start).toBe(buckets[i - 1]!.start + buckets[i - 1]!.step);
    expect(buckets[0]!.clipped).toBe(true);
    expect(buckets.filter((b) => b.clipped)).toHaveLength(1);
  });
});

describe("the motion over stepped frames", () => {
  // Frames a tenth of a second apart over 40 s around a ten-minute mark, where every tier switches at once.
  const at = T0 + 45;
  const held = heldOf(testHistory({ at, burstAgo: 3 * 3600 }));
  const frames = Array.from({ length: 400 }, (_, i) => T0 + i / 10);

  it("puts every grid line where the axis function puts its moment, fading it in by at most 0.01 a frame", () => {
    let before = new Map<string, number>();
    for (const t of frames) {
      const now = new Map<string, number>();
      forEachGridLine(t, W, (moment, step, x, alpha) => {
        expect(x).toBeCloseTo(axisX(t - moment, W), 9);
        expect(moment % step).toBe(0);
        const key = `${moment}`;
        const was = before.get(key);
        if (was !== undefined) expect(Math.abs(alpha - was)).toBeLessThan(0.01);
        // A line is born at "now" or at full opacity's edge, never in the middle at once.
        else if (before.size > 0) expect(alpha < 0.01 || t - moment < 0.2).toBe(true);
        now.set(key, alpha);
      });
      before = now;
    }
  });

  it("moves every point left and never right, and changes the line's shape by under half a pixel a frame", () => {
    let before = new Map<string, { cx: number; y: number }>();
    let top = 0;
    for (const t of frames) {
      const buckets = frame(held, t);
      const scale = scaleTop(buckets);
      const y = (v: number) => 61 * (1 - Math.min(v, scale) / scale);
      const now = new Map<string, { cx: number; y: number }>();
      for (const b of buckets) {
        if (!b.data) continue;
        const key = `${b.step}:${b.start}`;
        const point = { cx: b.cx, y: y(b.m) };
        const was = before.get(key);
        if (was) {
          expect(point.cx, key).toBeLessThanOrEqual(was.cx + 1e-9);
          if (scale === top) expect(Math.abs(point.y - was.y), key).toBeLessThan(0.5);
        }
        now.set(key, point);
      }
      before = now;
      top = scale;
    }
  });
});

describe("the scale", () => {
  it("lets a lone needle leave the scale, which keeps the normal rhythm readable", () => {
    // A burst of five seconds two hours back, in a ten-minute bucket.
    const at = T0;
    const buckets = frame(heldOf(testHistory({ at, burstAgo: 7200, figures: ["dns-queries"] })), at);
    const top = scaleTop(buckets);
    const needle = buckets.reduce((max, b) => Math.max(max, b.data ? b.highest : 0), 0);
    expect(needle).toBeGreaterThan(top);
    expect(buckets.filter((b) => b.data && b.highest > top)).toHaveLength(1);
    // The needle lifts the scale by at most half again its neighbors, not to its own height.
    const quiet = scaleTop(frame(heldOf(testHistory({ at, burstAgo: 3 * 86_400, figures: ["dns-queries"] })), at));
    expect(top).toBeLessThanOrEqual(1.5 * quiet);
    expect(needle).toBeGreaterThan(3 * top);
  });

  it("is 1 for a chart without data, which then is hatched from end to end", () => {
    const buckets = frame({ controllers: [], figures: new Map() }, T0);
    expect(scaleTop(buckets)).toBe(1);
    expect(buckets.every((b) => !b.data)).toBe(true);
  });
});

describe("gaps and restarts", () => {
  it("draws no data where the controller had none, and nothing before its start", () => {
    const at = T0;
    const buckets = frame(heldOf(testHistory({ at, startedAgo: 30 * 3600, gaps: [[3 * 3600, 2 * 3600]], figures: ["dns-queries"] })), at);
    const age = (b: Bucket) => at - b.start - b.step;
    expect(buckets.filter((b) => age(b) > 30 * 3600 + 3600).every((b) => !b.data)).toBe(true);
    expect(buckets.filter((b) => age(b) > 2 * 3600 + 600 && at - b.start < 3 * 3600 - 600).every((b) => !b.data)).toBe(true);
    expect(buckets.filter((b) => at - b.start < 3600).every((b) => b.data)).toBe(true);
  });
});

describe("the grid in local time", () => {
  it("puts the hour lines on the local hour across a change of daylight saving time", () => {
    // One hour more from the moment `T0 - 5 h` on, as in spring.
    const change = T0 - 5 * 3600 + 1800;
    const offset = (t: number) => (t >= change ? 7200 : 3600);
    let hours = 0;
    forEachGridLine(
      T0,
      W,
      (moment, step) => {
        if (step < 3600) return;
        hours += 1;
        expect((moment + offset(moment)) % 3600).toBe(0);
      },
      offset,
    );
    expect(hours).toBeGreaterThan(5);
  });
});

describe("the mock's canned history", () => {
  it("is the golden example's, every moment moved by the same whole seconds so that it ends now", () => {
    const now = Date.parse("2026-11-12T09:30:00.250Z");
    const frame = cannedMetricsHistory(now);
    const event = JSON.parse(frame.split("\n").find((line) => line.startsWith("data: "))!.slice(6)) as { history: HistoryFrame };
    const original = GOLDEN[0]!.history!;
    const shift = Date.parse(event.history.at) - Date.parse(original.at);
    expect(Math.abs(Date.parse(event.history.at) - now)).toBeLessThanOrEqual(500);
    expect(shift % 1000).toBe(0);
    const back = (stamp: string) => new Date(Date.parse(stamp) - shift).toISOString();
    expect(event.history.controllers.map((c) => (c.started ? { ...c, started: back(c.started) } : c))).toEqual(
      original.controllers.map((c) => (c.started ? { ...c, started: new Date(c.started).toISOString() } : c)),
    );
    expect(event.history.figures.map((f) => ({ ...f, tiers: f.tiers.map((t) => ({ ...t, start: back(t.start) })) }))).toEqual(
      original.figures.map((f) => ({ ...f, tiers: f.tiers.map((t) => ({ ...t, start: new Date(t.start).toISOString() })) })),
    );
  });
});

describe("the tiers behind the line", () => {
  it("draw every slot the rings hold: no hole where a tier hands over", () => {
    for (const offset of [0, 7.3, 333, 1799, 3599.9]) {
      const at = T0 + offset;
      const held = heldOf(testHistory({ at, figures: ["dns-queries", "dns-cache"] }));
      for (const name of ["dns-queries", "dns-cache"] as const) {
        // Only what the hour ring does not hold, if it is shorter than the reach, may lack data.
        const hours = held.figures.get(name)!.tiers.find((t) => t.step === 3600)!;
        const empty = frame(held, at, name).filter((b) => !b.data);
        expect(empty.filter((b) => b.start >= hours.first), `${name} at +${offset}`).toEqual([]);
        expect(empty.every((b) => b.step === 3600)).toBe(true);
      }
    }
  });

  it("hand over where the rings the history names end, so a longer ring draws further back", () => {
    const at = T0;
    const history = testHistory({ at, figures: ["dns-queries"] });
    const short = bucketsAt(heldOf(history).figures.get("dns-queries"), at);
    for (const tier of history.figures[0]!.tiers) if (tier.step_ms === 600_000) tier.ring = 43;
    const long = bucketsAt(heldOf(history).figures.get("dns-queries"), at);
    const tenMinutes = (list: Bucket[]) => list.filter((b) => b.step === 600).length;
    expect(tenMinutes(long)).toBeGreaterThan(tenMinutes(short));
  });
});
