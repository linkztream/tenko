// The words of a history chart (OPS-20): the readout of one bucket, under the pointer and as the
// slider's value text, and the text alternative of the whole chart, so the chart reads without
// being seen (docs/plans/dashboard-history-plan.md, sections 3, 4 and 6). Each tier is read at its
// own step, so a peak in an hour bucket is named with its hour.
import { si } from "../app/format/si";
import { formatDateTime, formatDuration, formatNumber, formatRelative, locale, t } from "../i18n";
import { REACH, type Bucket, type HistoryController, type MetricsMerge } from "./history";

export interface ChartContext {
  title: string;
  unit: string;
  merge: MetricsMerge;
  controllers: readonly HistoryController[];
  /** The top of the scale. */
  top: number;
}

/** A value with its unit, three significant digits and an SI suffix from 1,000 on: "0.25 ms", "752/s", "1.2K/s". */
export function withUnit(value: number, unit: string): string {
  const n = Math.abs(value) < 1000 ? formatNumber(value, { maximumSignificantDigits: 3 }) : si(value, locale());
  return !unit ? n : unit.startsWith("/") ? `${n}${unit}` : `${n}\u00a0${unit}`;
}

/** A moment as a clock time, with the weekday when it is not on the day of `at`. */
function clock(time: number, at: number, seconds = false): string {
  const otherDay = new Date(time * 1000).toDateString() !== new Date(at * 1000).toDateString();
  return formatDateTime(time * 1000, { weekday: otherDay ? "short" : undefined, hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined });
}

/** The controllers that started within the reach and have the history: their history before that is gone. */
function starts(ctx: ChartContext, at: number): HistoryController[] {
  return ctx.controllers.filter((c) => c.started !== null && !c.unsupported && at - c.started < REACH);
}

/** What a missing start says, for the one controller or for each of a cluster. */
function startNote(ctx: ChartContext, c: HistoryController, at: number): string {
  const time = clock(c.started!, at);
  return ctx.controllers.length === 1 ? t("metrics.history.started_one", { time }) : t("metrics.history.started_of", { node: String(c.node ?? "?"), time });
}

export interface Readout {
  when: string;
  value: string;
  rows: string[];
  notes: string[];
}

/** The readout of a bucket at the moment `at`. */
export function readout(ctx: ChartContext, b: Bucket, at: number): Readout {
  const end = b.start + b.step;
  const parts = { step: formatDuration(b.step), ago: formatRelative(end * 1000, at * 1000) };
  const fine = b.step < 60;
  const when =
    b.step === 1
      ? t("metrics.history.when_one", { start: clock(b.start, at, true), ...parts })
      : t("metrics.history.when_span", { start: clock(b.start, at, fine), end: clock(end, at, fine), ...parts });
  const out: Readout = { when, value: "", rows: [], notes: [] };
  const total = ctx.controllers.length;
  if (!b.data) {
    out.value = t("metrics.history.no_data");
    for (const c of starts(ctx, at)) if (b.start < c.started!) out.notes.push(startNote(ctx, c, at));
    return out;
  }
  out.value = b.step === 1 ? withUnit(b.mean, ctx.unit) : t("metrics.history.mean", { value: withUnit(b.mean, ctx.unit) });
  const lowest = withUnit(b.lowest, ctx.unit);
  const highest = withUnit(b.highest, ctx.unit);
  if (b.step > 1) out.rows.push(t(b.highest > ctx.top ? "metrics.history.band_above" : "metrics.history.band", { lowest, highest }));
  else if (b.highest > ctx.top) out.rows.push(t("metrics.history.above", { top: withUnit(ctx.top, ctx.unit) }));
  if (b.clipped) out.notes.push(t("metrics.history.clipped"));
  // Whole minutes from a minute on ("7 min of 10 min"), seconds below ("41 sec of 1 min").
  if (b.covered < b.step) out.notes.push(t("metrics.history.partial_time", { covered: formatDuration(b.covered >= 60 ? Math.floor(b.covered / 60) * 60 : Math.floor(b.covered)), step: parts.step }));
  if (total > 1) {
    if (b.controllers < total) out.notes.push(t("metrics.history.partial_controllers", { covered: b.controllers, total }));
    out.notes.push(t(`metrics.history.merge.${ctx.merge}`));
  }
  return out;
}

/** The readout as one sentence: the slider's value text. */
export function readoutText(ctx: ChartContext, b: Bucket, at: number): string {
  const r = readout(ctx, b, at);
  return `${ctx.title}, ${r.when}: ${[r.value, ...r.rows].join(". ")}.${r.notes.map((note) => ` ${note}`).join("")}`;
}

/** The range of `list`: the bucket with the lowest and the one with the highest value, and the mean over the covered time. */
function scan(list: readonly Bucket[]) {
  let lowest: Bucket | undefined;
  let highest: Bucket | undefined;
  let sum = 0;
  let time = 0;
  for (const b of list) {
    if (!b.data) continue;
    if (!lowest || b.lowest < lowest.lowest) lowest = b;
    if (!highest || b.highest > highest.highest) highest = b;
    sum += b.mean * b.covered;
    time += b.covered;
  }
  return lowest && highest ? { lowest, highest, mean: time > 0 ? sum / time : lowest.mean } : null;
}

/**
 * The text alternative of a chart: the number now, the last minute's range, the last hour's mean
 * and peak, the older days' peak with its span and their lowest, and where history is missing.
 */
export function altText(ctx: ChartContext, buckets: readonly Bucket[], at: number, now: number | null): string {
  const n = (v: number) => withUnit(v, "");
  const parts = [now == null ? t("metrics.history.alt_none_now", { name: ctx.title }) : t("metrics.history.alt_now", { name: ctx.title, value: withUnit(now, ctx.unit) })];
  const minute = scan(buckets.filter((b) => b.tier === 0 && at - b.start <= 60 + b.step));
  const hour = scan(buckets.filter((b) => at - b.start - b.step < 3600));
  const days = scan(buckets.filter((b) => at - b.start - b.step >= 3600));
  if (minute) parts.push(minute.highest.highest === 0 ? t("metrics.history.alt_minute_zero") : t("metrics.history.alt_minute", { lowest: n(minute.lowest.lowest), highest: n(minute.highest.highest) }));
  if (hour)
    parts.push(
      hour.highest.highest === 0
        ? t("metrics.history.alt_hour_zero")
        : t("metrics.history.alt_hour", { mean: n(hour.mean), highest: n(hour.highest.highest), time: clock(hour.highest.start, at) }),
    );
  if (days) {
    const peak = days.highest;
    parts.push(
      peak.highest === 0
        ? t("metrics.history.alt_days_zero")
        : t("metrics.history.alt_days", { highest: n(peak.highest), start: clock(peak.start, at), end: clock(peak.start + peak.step, at), lowest: n(days.lowest.lowest) }),
    );
  }
  for (const c of starts(ctx, at)) parts.push(startNote(ctx, c, at));
  if (!minute && !hour && !days) parts.push(t("metrics.history.alt_empty"));
  return parts.join(" ");
}
