// The contract of the dashboard's history (OPS-20) on the UI's side. The golden example of the
// `metrics` topic, docs/api/examples/metrics-stream.jsonl (one `data:` document a line: a
// `metrics.history`, then a `metrics.snapshot` with `closed`), is written byte for byte by the
// server's test `the_golden_stream_is_what_the_server_writes` (crates/tenko-api/src/dto/events.rs);
// here the same bytes are read with the generated types, the client's rules for the buckets are
// checked on them, and the parser of the previous UI release reads the new stream without harm.
// docs/api/examples/metrics-figures.json holds the number of every figure for the snapshot's
// cluster sample, which the server's `MetricsFigure::value` and the UI's `tileValue` both give.
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DHCP_TILES, DNS_TILES, HOST_TILES, RECURSION_TILES, TILES, tileValue, type TileName } from "../dashboard/metrics";
import { EventStream, type ApiEvent } from "./events";
import type { components } from "./generated/schema";

type S = components["schemas"];
type Tier = S["MetricsTier"];

// The parser of the last UI release before the history (`snapshotOf` and `pushSnapshot` of
// `ui/src/dashboard/metrics.ts` at commit 5e140a0a, as `liveMetrics.ts` calls them), copied
// here so that it stays what that release ships
// while the dashboard moves on: it takes the snapshots by their kind and keeps a minute of them.
const PREVIOUS = {
  SNAPSHOT_KIND: "metrics.snapshot",
  HISTORY: 60,
  isObject(value: unknown): value is Record<string, unknown> {
    return !!value && typeof value === "object" && !Array.isArray(value);
  },
  snapshotOf(data: Record<string, unknown>): S["MetricsSnapshot"] | null {
    if (data.kind !== PREVIOUS.SNAPSHOT_KIND) return null;
    const metrics = data.metrics;
    if (!PREVIOUS.isObject(metrics) || !Array.isArray(metrics.nodes) || !PREVIOUS.isObject(metrics.cluster)) return null;
    return metrics as unknown as S["MetricsSnapshot"];
  },
  keep<T>(list: readonly T[], item: T): T[] {
    const next = [...list, item];
    return next.length > PREVIOUS.HISTORY ? next.slice(next.length - PREVIOUS.HISTORY) : next;
  },
  push(history: PreviousHistory, snapshot: S["MetricsSnapshot"]): PreviousHistory {
    const nodes = new Map<number, readonly S["MetricsSample"][]>();
    for (const sample of snapshot.nodes) {
      if (sample.node == null) continue;
      nodes.set(sample.node, PREVIOUS.keep(history.nodes.get(sample.node) ?? [], sample));
    }
    return { cluster: PREVIOUS.keep(history.cluster, snapshot.cluster), nodes, latest: snapshot };
  },
  empty(): PreviousHistory {
    return { cluster: [], nodes: new Map(), latest: null };
  },
};

interface PreviousHistory {
  cluster: readonly S["MetricsSample"][];
  nodes: ReadonlyMap<number, readonly S["MetricsSample"][]>;
  latest: S["MetricsSnapshot"] | null;
}

const read = (path: string) => readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8");
const LINES = read("../../../docs/api/examples/metrics-stream.jsonl")
  .split("\n")
  .filter((line) => line.length > 0);
const FIGURES = JSON.parse(read("../../../docs/api/examples/metrics-figures.json")) as Record<string, number | null>;

interface MetricsEvent {
  topic: string;
  kind?: string;
  history?: S["MetricsHistory"];
  metrics?: S["MetricsSnapshot"];
}
const EVENTS = LINES.map((line) => JSON.parse(line) as MetricsEvent);

function historyOf(): S["MetricsHistory"] {
  const history = EVENTS[0]?.history;
  if (!history) throw new Error("the first golden event carries no history");
  return history;
}

function snapshotEvent(): S["MetricsSnapshot"] {
  const snapshot = EVENTS[1]?.metrics;
  if (!snapshot) throw new Error("the second golden event carries no snapshot");
  return snapshot;
}

/** The start of bucket `i` of a tier in milliseconds since the epoch. */
function startOf(tier: Tier, i: number): number {
  return Date.parse(tier.start) - (tier.covered_ms.length - 1 - i) * tier.step_ms;
}

/**
 * The client's rule for a `closed`: one bucket per start, a newer copy replacing the one held,
 * appended after the newest; null when a hole opens between the newest start held and the
 * oldest start of the closed buckets (the client then opens the stream again).
 */
function appendClosed(held: Tier, closed: Tier): Tier | null {
  const columns = ["lowest", "highest", "mean", "covered_ms", "controllers"] as const;
  const next = structuredClone(held);
  const first = startOf(held, 0);
  for (let i = 0; i < closed.covered_ms.length; i++) {
    const index = (startOf(closed, i) - first) / held.step_ms;
    if (index < 0) continue;
    if (index > next.covered_ms.length) return null;
    for (const column of columns) (next[column] as (number | null)[])[index] = (closed[column] as (number | null)[])[i] ?? null;
    if (index >= next.covered_ms.length - 1) next.open = false;
  }
  next.start = new Date(first + (next.covered_ms.length - 1) * held.step_ms).toISOString();
  const excess = next.covered_ms.length - (held.ring ?? Infinity);
  if (excess > 0) for (const column of columns) (next[column] as unknown[]).splice(0, excess);
  return next;
}

/** True when the two types are the same. */
type Equal<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

describe("the golden metrics stream", () => {
  it("holds a history first and then a snapshot, as a stream delivers them", () => {
    expect(EVENTS.map((event) => [event.topic, event.kind])).toEqual([
      ["metrics", "metrics.history"],
      ["metrics", "metrics.snapshot"],
    ]);
  });

  it("names the tiles' figures exactly: a figure is a tile", () => {
    const same: Equal<TileName, S["MetricsFigure"]> = true;
    expect(same).toBe(true);
    const tiles: readonly TileName[] = [...TILES, ...HOST_TILES, ...DNS_TILES, ...RECURSION_TILES, ...DHCP_TILES];
    expect([...tiles].sort()).toEqual(Object.keys(FIGURES).sort());
  });

  it("carries the history in columns with gaps as null and starts on the step", () => {
    const history = historyOf();
    expect(history.controllers.map((c) => [c.node, c.started != null, c.unsupported ?? false])).toEqual([
      [1, true, false],
      [2, true, false],
      [3, false, true],
    ]);
    const queries = history.figures[0]!;
    expect([queries.figure, queries.merge]).toEqual(["dns-queries", "sum"]);
    expect(history.figures.map((f) => f.merge)).toEqual(["sum", "ratio", "least_available"]);
    for (const figure of history.figures) {
      for (const tier of figure.tiers) {
        const n = tier.covered_ms.length;
        expect(n).toBeGreaterThan(0);
        for (const column of [tier.lowest, tier.highest, tier.mean, tier.controllers]) expect(column).toHaveLength(n);
        expect(tier.open).toBe(true);
        expect(tier.ring ?? 0).toBeGreaterThanOrEqual(n);
        for (let i = 0; i < n; i++) {
          expect(startOf(tier, i) % tier.step_ms).toBe(0);
          const data = tier.covered_ms[i]! > 0;
          expect(tier.covered_ms[i]!).toBeLessThanOrEqual(tier.step_ms);
          expect(tier.controllers[i]! > 0).toBe(data);
          for (const column of [tier.lowest, tier.highest, tier.mean]) expect(column[i] != null).toBe(data);
        }
      }
    }
    // Four significant digits, whole numbers without a fraction, null where no controller reported.
    expect(queries.tiers[0]!.lowest).toEqual([700, null, 1235, 9877, 752.3, 750]);
    expect(queries.tiers[0]!.controllers).toEqual([1, 0, 2, 2, 2, 2]);
    expect(history.figures[1]!.tiers[0]!.step_ms).toBe(5000);
  });

  it("appends the closed buckets of a snapshot by their start, the closed copy replacing the open one", () => {
    const seconds = historyOf().figures[0]!.tiers[0]!;
    const closed = snapshotEvent().closed![0]!;
    expect(closed.figure).toBe("dns-queries");
    const tier = closed.tiers[0]!;
    expect(tier.open).toBeUndefined();
    expect(tier.ring).toBeUndefined();
    expect(seconds.ring).toBe(71);
    const next = appendClosed(seconds, tier);
    expect(next).not.toBeNull();
    expect(next!.covered_ms).toEqual([1000, 0, 1000, 1000, 1000, 1000]);
    expect(next!.open).toBe(false);
    // A closed bucket two steps after the newest held leaves a hole: open the stream again.
    const later: Tier = { ...tier, start: new Date(Date.parse(tier.start) + 3000).toISOString() };
    expect(appendClosed(seconds, later)).toBeNull();
    // A re-sent older bucket (a late controller's part added) replaces the one held in place.
    const older: Tier = { ...tier, start: new Date(Date.parse(tier.start) - 3000).toISOString(), controllers: [3, 3] };
    expect(appendClosed(seconds, older)!.controllers).toEqual([1, 3, 3, 2, 2, 2]);
    // Appending beyond the ring drops the oldest buckets; the newest start moves on.
    const next1 = { ...tier, start: new Date(Date.parse(tier.start) + 2000).toISOString() };
    const grown = appendClosed({ ...seconds, ring: 6 }, next1)!;
    expect(grown.covered_ms).toHaveLength(6);
    expect(grown.controllers).toEqual([2, 2, 2, 2, 2, 2]);
    expect(grown.start).toBe(next1.start);
  });

  it("gives every figure the number its tile shows", () => {
    const cluster = snapshotEvent().cluster;
    for (const [name, expected] of Object.entries(FIGURES)) {
      const value = tileValue(name as TileName, cluster);
      if (expected === null) expect(value).toBeNull();
      else expect(value, name).toBeCloseTo(expected, 9);
    }
  });
});

describe("the previous UI release reads the new stream", () => {
  it("ignores the history event and the closed buckets and keeps drawing its sparkline", () => {
    const [history, snapshot] = EVENTS as [MetricsEvent, MetricsEvent];
    expect(PREVIOUS.snapshotOf(history as unknown as Record<string, unknown>)).toBeNull();
    const parsed = PREVIOUS.snapshotOf(snapshot as unknown as Record<string, unknown>);
    expect(parsed).not.toBeNull();
    const kept = PREVIOUS.push(PREVIOUS.empty(), parsed!);
    expect(kept.cluster).toHaveLength(1);
    expect(kept.nodes.get(1)).toHaveLength(1);
    expect(tileValue("dns-queries", kept.cluster[0]!)).toBe(750);
  });

  it("passes both events of the topic through the event stream to the same handler", () => {
    const listeners = new Map<string, ((e: Event) => void)[]>();
    const source = {
      readyState: 1,
      onopen: null,
      onerror: null,
      addEventListener(type: string, fn: (e: Event) => void) {
        listeners.set(type, [...(listeners.get(type) ?? []), fn]);
      },
      close() {},
    };
    const stream = new EventStream({ baseTopics: [], createEventSource: () => source as unknown as EventSource });
    const got: ApiEvent[] = [];
    let samples = PREVIOUS.empty();
    stream.subscribe("metrics", (event) => {
      got.push(event);
      const snapshot = PREVIOUS.snapshotOf(event.data);
      if (snapshot) samples = PREVIOUS.push(samples, snapshot);
    });
    stream.start();
    for (const line of LINES) {
      for (const fn of listeners.get("metrics") ?? []) fn(new MessageEvent("metrics", { data: line }));
    }
    expect(got.map((event) => event.data.kind)).toEqual(["metrics.history", "metrics.snapshot"]);
    expect(samples.cluster).toHaveLength(1);
    stream.stop();
  });
});
