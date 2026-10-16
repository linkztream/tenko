// A fake of the `metrics` stream of the start page, answered in the browser with `page.route`.
//
// WHY THE METRICS SCENARIOS OF SEVERAL CONTROLLERS FAKE THE STREAM: the e2e server is one
// controller, so it never publishes a snapshot with the samples of peers, a stale controller or
// one that runs an older build. The request of the tiles for the `metrics` topic (and only that
// stream: the tab's own stream names other topics) is answered with server-sent events whose data
// is shaped like `MetricsSnapshot` of docs/api/openapi.json, and every later connection of the
// tiles is refused, so the page keeps what it was given. The samples of the peers themselves come
// through `Metrics.Snapshot`, which the Rust tests cover.

import type { Page } from "@playwright/test";
import type { Schemas } from "./api";

export type MetricsSample = Schemas["MetricsSample"];
export type MetricsSnapshot = Schemas["MetricsSnapshot"];

/** The request the tiles make: the `metrics` topic alone. */
const STREAM = /\/api\/v1\/events\?topics=metrics(&|$)/;

/** One controller's sample; every figure can be changed with `patch`. */
export function sample(node: number | null, patch: Partial<MetricsSample> = {}): MetricsSample {
  return {
    node,
    at: "2026-10-14T12:00:00Z",
    interval_ms: 1000,
    api: { requests_per_second: 12.5, p50_ms: 0.8, p99_ms: 24 },
    store: { data_bytes: 4_096, file_bytes: 1_500_000, commit_p99_ms: 3.2 },
    raft: { role: node === null ? null : "follower", term: 9, lag: [] },
    jobs: { running: 2, waiting: 1 },
    ingest: { batches_per_second: 0.5, facts_per_second: 40 },
    sse: { subscribers: 4 },
    nodes: [],
    ...patch,
  };
}

/**
 * Leaves the start page that the sign-in fixture opened, so that its own stream (which would
 * reconnect while the page unloads) cannot reach the fake that is installed next.
 */
async function leaveStartPage(page: Page): Promise<void> {
  await page.goto("about:blank");
}

/**
 * Answers the metrics stream of the tiles with `snapshots`, one event each (ids 1, 2, ...), and
 * refuses every later connection. Call it before the page is opened.
 */
export async function fakeMetricsStream(page: Page, snapshots: MetricsSnapshot[]): Promise<{ connections: () => number }> {
  let connections = 0;
  await leaveStartPage(page);
  await page.route(STREAM, async (route) => {
    connections += 1;
    if (connections > 1) return route.abort("connectionrefused");
    const body = snapshots
      .map((snapshot, i) => `id: ${i + 1}\nevent: metrics\ndata: ${JSON.stringify({ topic: "metrics", kind: "metrics.snapshot", metrics: snapshot })}\n\n`)
      .join("");
    await route.fulfill({
      status: 200,
      headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" },
      body,
    });
  });
  return { connections: () => connections };
}

/** The tiles never get a sample: every connection of the stream is refused. */
export async function refuseMetricsStream(page: Page): Promise<void> {
  await leaveStartPage(page);
  await page.route(STREAM, (route) => route.abort("connectionrefused"));
}
