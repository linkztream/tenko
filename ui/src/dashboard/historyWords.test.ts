// The words of a history chart (OPS-20): the text alternative of each tile matches its data, and
// the readout says what a bucket is, what is missing and how the cluster combined it.
import { beforeEach, describe, expect, it } from "vitest";
import { setLocale } from "../i18n";
import { bucketsAt, heldOf, place, scaleTop, type Bucket, type HistoryController } from "./history";
import { testHistory } from "./historyTestData";
import { altText, readout, readoutText, withUnit, type ChartContext } from "./historyWords";

const AT = Date.parse("2026-11-12T14:00:00Z") / 1000;

function chart(options: Parameters<typeof testHistory>[0], controllers?: HistoryController[]) {
  const held = heldOf(testHistory(options));
  const buckets = bucketsAt(held.figures.get("dns-queries"), options.at);
  place(buckets, options.at, 249);
  const ctx: ChartContext = { title: "DNS queries", unit: "/s", merge: "sum", controllers: controllers ?? held.controllers, top: scaleTop(buckets) };
  return { buckets, ctx };
}

beforeEach(async () => {
  await setLocale("en");
});

describe("the text alternative", () => {
  it("names the figure now, the last minute's range, the last hour's peak and the days' peak with its span", () => {
    const { buckets, ctx } = chart({ at: AT, figures: ["dns-queries"], burstAgo: 5 * 3600 + 30 });
    const text = altText(ctx, buckets, AT, 1.2);
    const [now, minute, hour, days] = text.split(/(?<=\.) /);
    expect(now).toBe("DNS queries: 1.2/s now.");
    // The range of the last minute is the range of its one-second buckets.
    const lastMinute = buckets.filter((b) => b.step === 1 && AT - b.start <= 61);
    expect(minute).toBe(`Last minute: ${withUnit(Math.min(...lastMinute.map((b) => b.lowest)), "")} to ${withUnit(Math.max(...lastMinute.map((b) => b.highest)), "")}.`);
    expect(hour).toMatch(/^Last hour: mean [\d.]+, highest [\d.]+ at \d\d:\d\d [AP]M\.$/);
    // The burst five hours back stands in a ten-minute bucket: named with that bucket's span.
    const older = buckets.filter((b) => b.data && AT - b.start - b.step >= 3600);
    const peak = older.reduce((p, b) => (b.highest > p.highest ? b : p));
    const lowest = Math.min(...older.map((b) => b.lowest));
    expect([peak.step, peak.start]).toEqual([600, AT - 5 * 3600 - 600]);
    expect(days).toBe(`Last 2 days: highest ${withUnit(peak.highest, "")} between 08:50 AM and 09:00 AM, lowest ${withUnit(lowest, "")}.`);
  });

  it("says 0 throughout for a figure that never moved, and where the history begins after a restart", () => {
    const zero: Bucket[] = chart({ at: AT, figures: ["dns-queries"] }).buckets.map((b) => ({ ...b, lowest: 0, highest: 0, mean: 0 }));
    const { ctx } = chart({ at: AT, figures: ["dns-queries"], startedAgo: 3 * 3600 });
    expect(altText(ctx, zero, AT, 0)).toBe(
      "DNS queries: 0/s now. Last minute: 0 throughout. Last hour: 0 throughout. Last 2 days: 0 throughout. No history before 11:00 AM, when this controller started.",
    );
  });

  it("says that there is no history yet before the first bucket", () => {
    const empty = bucketsAt(undefined, AT);
    expect(altText({ title: "DNS queries", unit: "/s", merge: "sum", controllers: [], top: 1 }, empty, AT, null)).toBe("DNS queries: no figure now. No history yet.");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    const { buckets, ctx } = chart({ at: AT, figures: ["dns-queries"], startedAgo: 3 * 3600 });
    expect(altText(ctx, buckets, AT, null)).toMatch(/^DNS queries: inget värde nu\. Senaste minuten: .* Ingen historik före 11:00, då denna controller startade\.$/);
  });
});

describe("the readout", () => {
  it("gives a coarse bucket's span, mean and band, and the time it had data", () => {
    const { buckets, ctx } = chart({ at: AT, figures: ["dns-queries"], gaps: [[2 * 3600 + 300, 2 * 3600 + 120]] });
    // The ten-minute bucket of 11:50, in which three minutes had no data.
    const b = buckets.find((x) => x.step === 600 && x.start === AT - 2 * 3600 - 600)!;
    const r = readout(ctx, b, AT);
    expect(r.when).toBe("11:50 AM to 12:00 PM · 10 min · 2 hours ago");
    expect(r.value).toMatch(/^[\d.]+\/s mean$/);
    expect(r.rows).toEqual([expect.stringMatching(/^Lowest [\d.]+\/s, highest [\d.]+\/s$/)]);
    expect(r.notes).toEqual(["7 min of 10 min with data."]);
  });

  it("says why a bucket of a cluster lacks a controller and how the cluster combined it", () => {
    const controllers: HistoryController[] = [
      { node: 1, started: AT - 86_400, unsupported: false },
      { node: 2, started: AT - 3600, unsupported: false },
      { node: 3, started: null, unsupported: true },
    ];
    const { buckets, ctx } = chart({ at: AT, figures: ["dns-queries"] }, controllers);
    const b = { ...buckets.find((x) => x.step === 60)!, controllers: 2 };
    expect(readout(ctx, b, AT).notes).toEqual([
      "2 of 3 controllers reported.",
      "Sum of the controllers: the mean is exact; the true range lies inside the lowest and highest shown.",
    ]);
    const old = { ...buckets[0]!, data: false };
    expect(readoutText(ctx, old, AT)).toBe(
      "DNS queries, Tue 02:00 PM to Tue 03:00 PM · 1 hr · 2 days ago: No data. Controller 1 started at Wed 02:00 PM; its history before that is missing. Controller 2 started at 01:00 PM; its history before that is missing.",
    );
  });

  it("marks a value above the scale", () => {
    const { buckets, ctx } = chart({ at: AT, figures: ["dns-queries"] });
    const b = buckets.find((x) => x.step === 1 && x.data)!;
    expect(readout({ ...ctx, top: b.mean / 2 }, b, AT).rows).toEqual([`Above the scale of ${withUnit(b.mean / 2, "/s")}`]);
    const coarse = buckets.find((x) => x.step === 3600 && x.data)!;
    expect(readout({ ...ctx, top: coarse.highest / 2 }, coarse, AT).rows[0]).toMatch(/\(above the scale\)$/);
  });
});
