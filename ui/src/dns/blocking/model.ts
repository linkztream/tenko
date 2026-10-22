// The pure parts of the blocking page: the window, the pause and its remaining time, the bars
// of the hours, the share in percent, the kind of a client and the name of a list.
import type { BlockingPause, BlockingStats, BlockingWindow } from "./api";

export const WINDOWS: readonly BlockingWindow[] = ["24h", "7d"];

/** The window of the `window` query parameter; anything but `7d` is the default of 24 hours. */
export function windowOf(value: unknown): BlockingWindow {
  return value === "7d" ? "7d" : "24h";
}

/** Days a window covers. */
export function windowDays(window: BlockingWindow): number {
  return window === "7d" ? 7 : 1;
}

/** Whether the log keeps fewer days than the window asks for. */
export function logIsShort(window: BlockingWindow, logDays: number): boolean {
  return logDays < windowDays(window);
}

/** The pause buttons: minutes, or absent for "until resumed". */
export const PAUSES: readonly { id: string; minutes?: number }[] = [
  { id: "5", minutes: 5 },
  { id: "15", minutes: 15 },
  { id: "60", minutes: 60 },
  { id: "open" },
];

export type PauseState = "on" | "timed" | "open";

export function pauseState(paused: BlockingPause | null | undefined): PauseState {
  if (!paused) return "on";
  return paused.until ? "timed" : "open";
}

/** Whole seconds until a timed pause ends (0 once it has), or null for no pause or one without an end. */
export function secondsLeft(paused: BlockingPause | null | undefined, now: number): number | null {
  if (!paused?.until) return null;
  const end = Date.parse(paused.until);
  if (Number.isNaN(end)) return null;
  return Math.max(0, Math.ceil((end - now) / 1000));
}

/** Whether a timed pause has ended at `now`. */
export function pauseEnded(paused: BlockingPause | null | undefined, now: number): boolean {
  const left = secondsLeft(paused, now);
  return left !== null && left <= 0;
}

/** One hour of the bar chart: heights as fractions (0 to 1). */
export interface HourBar {
  start: string;
  queries: number;
  blocked: number;
  /** The height of the bar in the height of the chart: the busiest hour fills it. */
  total: number;
  /** The blocked part of the bar. */
  part: number;
}

/** The bars of the hours, oldest first. */
export function hourBars(hours: BlockingStats["hours"]): HourBar[] {
  const peak = Math.max(1, ...hours.map((h) => h.queries));
  return hours.map((h) => ({
    start: h.start,
    queries: h.queries,
    blocked: h.blocked,
    total: h.queries / peak,
    part: h.queries > 0 ? Math.min(1, h.blocked / h.queries) : 0,
  }));
}

/** A fraction as a CSS percentage with one decimal. */
export function pct(fraction: number): string {
  return `${Math.round(Math.min(1, Math.max(0, fraction)) * 1000) / 10}%`;
}

/** The kind of a client in the top list: a pseudonym, an address, or withheld (absent). */
export function clientKind(client: string | null | undefined): "pseudonym" | "address" | "withheld" {
  if (!client) return "withheld";
  return client.startsWith("p:") ? "pseudonym" : "address";
}

/** The name of a list by its id; absent for a list deleted since. */
export function listName(lists: BlockingStats["lists"], id: string | null | undefined): string | undefined {
  if (!id) return undefined;
  return lists.find((l) => l.list === id)?.name ?? undefined;
}

/** The share of `part` in `whole` (0 to 1), or 0 without a whole. */
export function share(part: number, whole: number): number {
  return whole > 0 ? part / whole : 0;
}
