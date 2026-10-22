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
import { mockMetricsHistory } from "../../src/api/mock/metrics-model";
import type { Schemas } from "./api";

export type MetricsSample = Schemas["MetricsSample"];
export type MetricsSnapshot = Schemas["MetricsSnapshot"];
export type MetricsDns = Schemas["MetricsDns"];

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
 * The `dns` part of a sample of a controller that runs the `dns` role: about 1,250 queries per
 * second, four block lists and DoT and DoH served; every figure can be changed with `patch`.
 */
export function dnsPart(patch: Partial<MetricsDns> = {}): MetricsDns {
  return {
    queries_per_second: 1_250,
    transports: { udp: 1_000, tcp: 50, dot: 150, doh: 50 },
    p50_ms: 0.3,
    p99_ms: 18,
    rcodes: { noerror: 1_000, nxdomain: 150, servfail: 50, refused: 25, other: 25 },
    cache: { hit_ratio: 0.82, hits_per_second: 410, misses_per_second: 90, stale_per_second: 1.5, entries: 8_400 },
    upstreams: { queries_per_second: 90, p99_ms: 42 },
    blocked: [
      { list: "ads", per_second: 30 },
      { list: "malware", per_second: 2 },
      { list: "trackers", per_second: 12 },
      { list: "telemetry", per_second: 5 },
    ],
    connections: { dot: 6, doh: 3 },
    log_dropped_per_second: 0,
    ...patch,
  };
}

/**
 * The last `count` snapshots of one controller, one second apart, with the `dns` part unless
 * `dns` is false: the samples of the dev mock (src/api/mock/metrics-model.ts), whose figures
 * move, so every sparkline and bar chart draws.
 */
export function mockHistory(count: number, dns = true, dhcp = false): MetricsSnapshot[] {
  return mockMetricsHistory(count, count, { dns, dhcp });
}

// WP8.7: the `dhcp` part of a sample.
export type MetricsDhcp = Schemas["MetricsDhcp"];

/**
 * The `dhcp` part of a sample of a controller that runs the `dhcp` role: 40 leases per second,
 * four scopes with the three fullest, DDNS writing names; every figure can be changed with `patch`.
 */
export function dhcpPart(patch: Partial<MetricsDhcp> = {}): MetricsDhcp {
  return {
    leases_per_second: 40,
    ack_p99_ms: 8.5,
    naks_per_second: 0.5,
    declines_per_second: 0,
    active_leases: 1_200,
    abandoned_leases: 2,
    scopes: 4,
    fullest: [
      { scope: "192.0.2.0/26", utilization: 0.9 },
      { scope: "198.51.100.0/24", utilization: 0.6 },
      { scope: "203.0.113.0/25", utilization: 0.3 },
    ],
    ddns: { written: 6, removed: 2, refused: 1, failed: 0, skipped: 1, dropped: 0, queue: 3 },
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
