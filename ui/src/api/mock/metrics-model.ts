// The samples of the `metrics` topic in the mock (OPS-20): one snapshot per second of a single
// controller, shaped like `MetricsSnapshot` of docs/api/openapi.json. The figures wave slowly
// around a plausible level, so the sparklines and the bar charts of the start page move; the
// same second always gives the same snapshot. A controller with the `dns` role adds the `dns`
// part (queries, cache, answers by RCODE, block lists, upstreams, DoT and DoH); one without it
// sends none, as the server does. `e2e/support/metrics-mock.ts` uses the same samples.
import type { components } from "../generated/schema";

type S = components["schemas"];
export type MockMetricsSnapshot = S["MetricsSnapshot"];
type Sample = S["MetricsSample"];
type Dns = S["MetricsDns"];

export interface MockMetricsOptions {
  /** Whether the controller runs the `dns` role. */
  dns: boolean;
  /** The id of the controller. */
  node?: number;
  // WP8.7: the `dhcp` role.
  /** Whether the controller runs the `dhcp` role. */
  dhcp?: boolean;
}

// WP8.7: the `dhcp` part of a sample: about 40 leases a second, four scopes, DDNS on.
function dhcpPart(second: number): S["MetricsDhcp"] {
  const leases = round(wave(40, 0.4, 35, second), 0);
  return {
    leases_per_second: leases,
    ack_p99_ms: leases > 0 ? round(wave(9, 0.4, 22, second)) : null,
    naks_per_second: round(wave(0.4, 1, 27, second)),
    declines_per_second: second % 45 < 2 ? 1 : 0,
    active_leases: 1_180 + (second % 120),
    abandoned_leases: 2,
    scopes: 4,
    fullest: [
      { scope: "192.0.2.0/26", utilization: round(wave(0.86, 0.04, 90, second), 2) },
      { scope: "198.51.100.0/24", utilization: round(wave(0.61, 0.05, 70, second), 2) },
      { scope: "203.0.113.0/25", utilization: round(wave(0.33, 0.1, 60, second), 2) },
    ],
    ddns: {
      written: round(wave(6, 0.5, 31, second), 0),
      removed: round(wave(2, 0.8, 41, second), 0),
      refused: second % 30 < 3 ? 1 : 0,
      failed: 0,
      skipped: round(wave(1, 1, 19, second)),
      dropped: 0,
      queue: second % 7,
    },
  };
}

/** A fixed pseudo-random number from -1 to 1 for a second and a salt. */
function jitter(second: number, salt: number): number {
  const x = Math.sin(second * 12.9898 + salt * 78.233) * 43_758.5453;
  return (x - Math.floor(x)) * 2 - 1;
}

/**
 * A level that waves by `swing` (a fraction) with a period of `period` seconds, with a third of
 * the swing as noise so the line does not look drawn.
 */
function wave(level: number, swing: number, period: number, second: number, phase = 0): number {
  const slow = Math.sin((2 * Math.PI * (second + phase)) / period);
  return Math.max(0, level * (1 + swing * (0.67 * slow + 0.33 * jitter(second, period + phase))));
}

/** Rounded to `digits` decimals. */
function round(value: number, digits = 1): number {
  const f = 10 ** digits;
  return Math.round(value * f) / f;
}

function dnsPart(second: number): Dns {
  const queries = round(wave(1_200, 0.25, 40, second), 0);
  const hits = round(wave(420, 0.2, 23, second, 5), 0);
  const misses = round(wave(90, 0.5, 17, second), 0);
  const nxdomain = round(wave(140, 0.3, 29, second, 7), 0);
  const servfail = round(wave(12, 0.9, 13, second), 0);
  const refused = round(wave(6, 0.8, 19, second, 3), 0);
  const other = 2;
  const noerror = Math.max(0, queries - nxdomain - servfail - refused - other);
  const dot = round(queries * 0.12, 0);
  const doh = round(queries * 0.05, 0);
  const tcp = round(queries * 0.04, 0);
  return {
    queries_per_second: queries,
    transports: { udp: queries - dot - doh - tcp, tcp, dot, doh },
    p50_ms: round(wave(0.4, 0.3, 11, second)),
    p99_ms: round(wave(16, 0.4, 21, second), 0),
    rcodes: { noerror, nxdomain, servfail, refused, other },
    cache: {
      hit_ratio: hits + misses > 0 ? hits / (hits + misses) : null,
      hits_per_second: hits,
      misses_per_second: misses,
      stale_per_second: round(wave(1.2, 1, 31, second)),
      entries: 8_400 + (second % 600) * 3,
    },
    upstreams: { queries_per_second: misses, p99_ms: round(wave(38, 0.3, 27, second), 0) },
    blocked: [
      { list: "ads", per_second: round(wave(28, 0.4, 15, second), 0) },
      { list: "trackers", per_second: round(wave(11, 0.5, 26, second, 4), 0) },
      { list: "malware", per_second: round(wave(1.5, 1, 33, second)) },
      { list: "telemetry", per_second: round(wave(4, 0.6, 18, second, 9), 0) },
    ],
    connections: { dot: 6 + (second % 5), doh: 3 },
    log_dropped_per_second: 0,
  };
}

/** The snapshot of second `second` (any integer: seconds since some start), taken at `at`. */
export function mockMetricsSnapshot(second: number, options: MockMetricsOptions, at: Date = new Date()): MockMetricsSnapshot {
  const node = options.node ?? 1;
  const lag = [{ node, entries: 0 }];
  const nodes = [{ node: 1001, buffer_batches: round(wave(3, 1, 37, second), 0), drops: 0 }];
  const own = (id: number | null): Sample => ({
    node: id,
    at: at.toISOString(),
    interval_ms: 1000,
    api: { requests_per_second: round(wave(14, 0.5, 20, second)), p50_ms: round(wave(0.9, 0.3, 9, second)), p99_ms: round(wave(22, 0.4, 14, second), 0) },
    store: { data_bytes: 6_291_456, file_bytes: 25_165_824, commit_p99_ms: round(wave(3.2, 0.5, 12, second)) },
    raft: { role: id === null ? null : "leader", term: 3, lag },
    jobs: { running: second % 30 < 12 ? 1 : 0, waiting: 1 },
    ingest: { batches_per_second: round(wave(0.6, 1, 25, second)), facts_per_second: round(wave(35, 1, 25, second), 0) },
    sse: { subscribers: 3 },
    nodes,
    dns: options.dns ? dnsPart(second) : null,
    // WP8.7: the `dhcp` part.
    dhcp: options.dhcp ? dhcpPart(second) : null,
  });
  return { cluster: own(null), nodes: [own(node)] };
}

/**
 * The last `count` snapshots up to second `second`, oldest first, one second apart and ending
 * at `now`: what the page would have collected had it listened that long.
 */
export function mockMetricsHistory(count: number, second: number, options: MockMetricsOptions, now: Date = new Date()): MockMetricsSnapshot[] {
  return Array.from({ length: count }, (_, i) => {
    const back = count - 1 - i;
    return mockMetricsSnapshot(second - back, options, new Date(now.getTime() - back * 1000));
  });
}
