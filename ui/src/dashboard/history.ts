// The history of the dashboard's tiles (OPS-20) on the client, and the geometry of the chart that
// draws it (docs/plans/dashboard-history-plan.md, sections 1 to 3).
//
// The store: the first `metrics.history` event of a stream gives every figure's tiers; the
// `closed` buckets of each later snapshot are appended by their start, a later copy replacing the
// one held, and the oldest beyond the tier's ring dropped. The client never aggregates. A closed
// bucket that would leave a hole, or a figure or tier the history lacks, means the stream must be
// opened again for a fresh history (`withClosed` returns null).
//
// The chart: one continuous axis x = W · (1 − asinh(age / τ) / asinh(A / τ)), straight near "now"
// and logarithmic toward the past, with no border anywhere. Five tiers about ten times apart lie
// behind the line; each finer tier is drawn until the next coarser bucket starts, so every drawn
// bucket is whole, and during the last coarser step before finer buckets would give way their
// drawn values and centers slide toward the coarser bucket's, so the switch shows nothing. Times
// are seconds since the epoch on the controller's clock.
import type { components } from "../api/generated/schema";
import { niceCeiling, type TileName } from "./metrics";

type S = components["schemas"];
export type HistoryFrame = S["MetricsHistory"];
export type MetricsMerge = S["MetricsMerge"];
type WireTier = S["MetricsTier"];

/** The kind of the first event of the `metrics` topic. */
export const HISTORY_KIND = "metrics.history";

/** One tier as the client holds it: the columns of the wire, its step and the start of its oldest bucket in seconds. */
export interface Tier {
  step: number;
  first: number;
  ring: number;
  lowest: readonly (number | null)[];
  highest: readonly (number | null)[];
  mean: readonly (number | null)[];
  /** Milliseconds with data per bucket, as the wire says. */
  covered: readonly number[];
  controllers: readonly number[];
}

export interface FigureHistory {
  merge: MetricsMerge;
  /** Finest first. */
  tiers: readonly Tier[];
}

export interface HistoryController {
  node: number | null;
  /** Seconds; null for a controller without the history. */
  started: number | null;
  unsupported: boolean;
}

export interface HeldHistory {
  controllers: readonly HistoryController[];
  figures: ReadonlyMap<TileName, FigureHistory>;
}

function seconds(stamp: string | null | undefined): number | null {
  const ms = stamp == null ? Number.NaN : Date.parse(stamp);
  return Number.isFinite(ms) ? ms / 1000 : null;
}

/** A tier of the wire, or null when it is not one the contract allows (columns of unequal length, no start). */
function tierOf(wire: WireTier): Tier | null {
  const n = wire.covered_ms.length;
  const start = seconds(wire.start);
  const step = wire.step_ms / 1000;
  if (start === null || !(step > 0) || n === 0) return null;
  if ([wire.lowest, wire.highest, wire.mean, wire.controllers].some((column) => column.length !== n)) return null;
  return {
    step,
    first: start - (n - 1) * step,
    ring: wire.ring ?? Infinity,
    lowest: wire.lowest,
    highest: wire.highest,
    mean: wire.mean,
    covered: wire.covered_ms,
    controllers: wire.controllers,
  };
}

/** The history a `metrics.history` event gives; it replaces whatever the client held. */
export function heldOf(frame: HistoryFrame): HeldHistory {
  const figures = new Map<TileName, FigureHistory>();
  for (const figure of frame.figures) {
    const tiers = figure.tiers.map(tierOf).filter((tier): tier is Tier => tier !== null);
    figures.set(figure.figure, { merge: figure.merge, tiers });
  }
  const controllers = frame.controllers.map((c) => ({ node: c.node ?? null, started: seconds(c.started), unsupported: c.unsupported ?? false }));
  return { controllers, figures };
}

/** `held` with the closed buckets of one tier appended, or null on a hole. */
function appended(held: Tier, closed: Tier): Tier | null {
  const lowest = [...held.lowest];
  const highest = [...held.highest];
  const mean = [...held.mean];
  const covered = [...held.covered];
  const controllers = [...held.controllers];
  for (let i = 0; i < closed.covered.length; i++) {
    const index = Math.round((closed.first + i * closed.step - held.first) / held.step);
    if (index < 0) continue;
    if (index > covered.length) return null;
    lowest[index] = closed.lowest[i] ?? null;
    highest[index] = closed.highest[i] ?? null;
    mean[index] = closed.mean[i] ?? null;
    covered[index] = closed.covered[i] ?? 0;
    controllers[index] = closed.controllers[i] ?? 0;
  }
  const excess = Math.max(0, covered.length - held.ring);
  for (const column of [lowest, highest, mean, covered, controllers]) column.splice(0, excess);
  return { ...held, first: held.first + excess * held.step, lowest, highest, mean, covered, controllers };
}

/** The history with a snapshot's `closed` appended; null when the stream must be opened again. */
export function withClosed(held: HeldHistory, closed: readonly S["MetricsClosed"][]): HeldHistory | null {
  if (closed.length === 0) return held;
  const figures = new Map(held.figures);
  for (const { figure, tiers } of closed) {
    const own = figures.get(figure);
    if (!own) return null;
    const next = [...own.tiers];
    for (const wire of tiers) {
      const tier = tierOf(wire);
      const at = next.findIndex((t) => t.step === tier?.step);
      if (!tier || at < 0) return null;
      const merged = appended(next[at]!, tier);
      if (!merged) return null;
      next[at] = merged;
    }
    figures.set(figure, { ...own, tiers: next });
  }
  return { ...held, figures };
}

// ---------------------------------------------------------------------------------------------
// The axis

/** The knee of the axis: below about τ seconds of age the axis is linear. */
export const TAU = 20;
/** The reach of the chart: two days (DH-Q2). */
export const REACH = 2 * 86_400;
const SPAN = Math.asinh(REACH / TAU);
/** Ages with a label under the axis. */
export const AGE_LABELS = [10, 60, 600, 3600, 21_600, 86_400] as const;

/** The position of an age (seconds) on a chart `width` wide. */
export function axisX(age: number, width: number): number {
  return width * (1 - Math.asinh(Math.max(0, age) / TAU) / SPAN);
}

/** The pixels per second at an age: the axis function's slope. */
function pace(age: number, width: number): number {
  return width / (SPAN * Math.sqrt(age * age + TAU * TAU));
}

/** A drawn bucket: its slot and values, and its place in the newest frame (`place`). */
export interface Bucket {
  start: number;
  step: number;
  /** 0 the finest tier, 4 the coarsest. */
  tier: number;
  /** True when the bucket has data. */
  data: boolean;
  lowest: number;
  highest: number;
  mean: number;
  /** Seconds with data. */
  covered: number;
  controllers: number;
  /** The bucket starts before the reach: only its newer part is drawn. */
  clipped: boolean;
  /** The coarser bucket this one gives way to, while it has data, and when that happens. */
  parent: { lowest: number; highest: number; mean: number; mid: number; switchAt: number; step: number } | null;
  x0: number;
  x1: number;
  cx: number;
  /** The drawn mean, highest and lowest, slid toward the parent's. */
  m: number;
  h: number;
  l: number;
}

/** The values of the slot that starts at `start` in `tier`, or undefined when the client holds none there. */
function slot(tier: Tier | undefined, start: number) {
  if (!tier) return undefined;
  const i = Math.round((start - tier.first) / tier.step);
  if (i < 0 || i >= tier.covered.length) return undefined;
  const covered = tier.covered[i] ?? 0;
  const mean = tier.mean[i];
  if (!(covered > 0) || mean == null) return null;
  return { lowest: tier.lowest[i] ?? mean, highest: tier.highest[i] ?? mean, mean, covered: covered / 1000, controllers: tier.controllers[i] ?? 0 };
}

function bucket(start: number, step: number, tier: number, v: ReturnType<typeof slot>, clipped: boolean, parent: Bucket["parent"]): Bucket {
  return { start, step, tier, data: !!v, lowest: v?.lowest ?? 0, highest: v?.highest ?? 0, mean: v?.mean ?? 0, covered: v?.covered ?? 0, controllers: v?.controllers ?? 0, clipped, parent, x0: 0, x1: 0, cx: 0, m: 0, h: 0, l: 0 };
}

/**
 * The buckets a chart draws at `at` (the second it stands in), oldest first. Each coarser bucket is
 * drawn from the finest tier that holds all of it, so every drawn bucket is whole: a tier gives way
 * at the first start of the next coarser step at or after its oldest bucket (about 60 s, 9 min,
 * 50 min and 5 h back with full rings of 71, 61, 61 and 37), and a tier the history lacks or that
 * holds too little leaves its ages to the next. A slot without data is hatched; the finest tier
 * stops at its newest bucket, and the line runs on from there to the right edge. Without any tier
 * the chart is one bucket of no data.
 */
export function bucketsAt(figure: FigureHistory | undefined, at: number): Bucket[] {
  const now = Math.floor(at);
  const tiers = (figure?.tiers ?? []).filter((t) => t.covered.length > 0).sort((a, b) => a.step - b.step);
  if (tiers.length === 0) return [bucket(now - REACH, REACH, 0, null, false, null)];
  const parts: Bucket[][] = [];
  let edge = now;
  tiers.forEach((held, tier) => {
    const { step } = held;
    const next = tiers[tier + 1];
    const low = next ? Math.min(edge, Math.ceil(held.first / next.step) * next.step) : now - REACH;
    // A finer bucket gives way when the ring no longer holds the start of its coarser bucket: in
    // its last coarser step before that its drawn values slide toward the coarser bucket's.
    const reach = (held.covered.length - 1) * step;
    const list: Bucket[] = [];
    for (let b = Math.floor((edge - step) / step) * step; b + step > low; b -= step) {
      const v = slot(held, b);
      // Newer than anything held (the newest buckets are still on their way): not drawn.
      if (v === undefined && b > held.first) continue;
      const start = next ? Math.floor(b / next.step) * next.step : 0;
      const p = next && v ? slot(next, start) : null;
      const parent = next && p ? { lowest: p.lowest, highest: p.highest, mean: p.mean, mid: start + next.step / 2, switchAt: start + reach, step: next.step } : null;
      list.push(bucket(b, step, tier, v, b < now - REACH, parent));
    }
    parts.push(list.reverse());
    edge = low;
  });
  return parts.reverse().flat();
}

/**
 * The top of the scale (DH-Q6 (b)): `fixed` for a share in percent (100), otherwise the highest after
 * holding each lone needle to half again the highest of its two neighbors on each side, rounded up to
 * a round number; a needle above it is drawn to the top with a caret. 1 for a chart without data.
 */
export function scaleTop(buckets: readonly Bucket[], fixed?: number): number {
  if (fixed !== undefined) return fixed;
  let held = 0;
  buckets.forEach((b, i) => {
    if (!b.data) return;
    let near = 0;
    for (const n of [buckets[i - 2], buckets[i - 1], buckets[i + 1], buckets[i + 2]]) if (n?.data) near = Math.max(near, n.highest);
    held = Math.max(held, near > 0 ? Math.min(b.highest, 1.5 * near) : b.highest);
  });
  return niceCeiling(held * 1.04);
}

/** Places the buckets on a chart `width` wide at the moment `at`, with the slide toward the coarser buckets. */
export function place(buckets: Bucket[], at: number, width: number): void {
  for (const b of buckets) {
    b.x0 = axisX(at - Math.max(b.start, at - REACH), width);
    b.x1 = axisX(at - b.start - b.step, width);
    b.cx = (b.x0 + b.x1) / 2;
    const p = b.parent;
    const w = p ? Math.min(1, Math.max(0, (p.switchAt - at) / p.step)) : 1;
    b.m = b.mean;
    b.h = b.highest;
    b.l = b.lowest;
    if (p && w < 1) {
      b.cx = w * b.cx + (1 - w) * axisX(at - p.mid, width);
      b.m = w * b.mean + (1 - w) * p.mean;
      b.h = w * b.highest + (1 - w) * p.highest;
      b.l = w * b.lowest + (1 - w) * p.lowest;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// The grid of moments

/** The steps of the grid's moments, coarsest first: a moment's line belongs to its coarsest step. */
const GRID_STEPS = [86_400, 21_600, 3600, 900, 300, 60, 15, 5] as const;
/** A line fades in once its neighbors are this many pixels away, and is fully drawn 4 px later. */
const GRID_MIN = 3;

const offsets = new Map<number, number>();
/** The browser's offset from UTC at a moment, in seconds, from the date itself (daylight saving time included). */
export function localOffset(t: number): number {
  const hour = Math.floor(t / 3600);
  let offset = offsets.get(hour);
  if (offset === undefined) {
    if (offsets.size > 512) offsets.clear();
    offset = -new Date(t * 1000).getTimezoneOffset() * 60;
    offsets.set(hour, offset);
  }
  return offset;
}

/** A moment's time on the clock of a step: local time for an hour and longer, UTC below (the same moments, as every offset is whole quarters of an hour). */
function clockOf(moment: number, step: number, offset: (t: number) => number): number {
  return step > 900 ? moment + offset(moment) : moment;
}

/**
 * Calls `line` for every moment of the grid on a chart `width` wide at `at`, with its position and
 * opacity: whole days, quarters of a day, hours and so on down to 5 s in local time, each drawn where
 * it stands (not rounded to a pixel), faded by how close its neighbors are. The moments are found by
 * walking real time, so on a day with a change of daylight saving time a repeated hour has both its
 * lines and a skipped hour none.
 */
export function forEachGridLine(at: number, width: number, line: (moment: number, step: number, x: number, alpha: number) => void, offset = localOffset): void {
  GRID_STEPS.forEach((step, i) => {
    // Beyond this age the lines of this step would stand closer than GRID_MIN.
    const far = Math.min(REACH, Math.sqrt(Math.max(0, ((step * width) / (SPAN * GRID_MIN)) ** 2 - TAU * TAU)));
    const coarser = GRID_STEPS[i - 1];
    const walk = Math.min(step, 900);
    for (let moment = Math.floor(at / walk) * walk; at - moment <= far; moment -= walk) {
      if (clockOf(moment, step, offset) % step !== 0) continue;
      if (coarser && clockOf(moment, coarser, offset) % coarser === 0) continue;
      const age = at - moment;
      const alpha = Math.min(1, (step * pace(age, width) - GRID_MIN) / 4);
      if (alpha > 0) line(moment, step, axisX(age, width), alpha);
    }
  });
}
