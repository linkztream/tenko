import { describe, expect, it } from "vitest";
import { emptyHistory, pushSnapshot, ratioBuckets, windowRatio, type MetricsDns, type MetricsHistory, type MetricsSample } from "./metrics";

function dns(hits: number, misses: number, noerror = 0, nxdomain = 0): MetricsDns {
  return {
    queries_per_second: hits + misses,
    transports: { udp: 0, tcp: 0, dot: 0, doh: 0 },
    p50_ms: null,
    p99_ms: null,
    rcodes: { noerror, nxdomain, servfail: 0, refused: 0, other: 0 },
    cache: { hit_ratio: hits + misses > 0 ? hits / (hits + misses) : null, hits_per_second: hits, misses_per_second: misses, stale_per_second: 0, entries: 0 },
    upstreams: { queries_per_second: 0 },
    blocked: [],
    connections: null,
    log_dropped_per_second: 0,
  };
}

function sample(part: MetricsDns | null): MetricsSample {
  return {
    node: null,
    at: "2026-10-14T12:00:00Z",
    interval_ms: 1000,
    api: { requests_per_second: 0, p50_ms: 0, p99_ms: 0 },
    store: { data_bytes: 0, commit_p99_ms: null },
    raft: { role: null, term: 0, lag: [] },
    jobs: { running: 0, waiting: 0 },
    ingest: { batches_per_second: 0, facts_per_second: 0 },
    sse: { subscribers: 0 },
    nodes: [],
    dns: part,
  };
}

function historyOf(parts: (MetricsDns | null)[]): MetricsHistory {
  return parts.reduce((h, part) => pushSnapshot(h, { nodes: [], cluster: sample(part) }), emptyHistory());
}

const quiet = (n: number) => Array.from({ length: n }, () => dns(0, 0));

describe("windowRatio", () => {
  it("sums hits and misses over the window instead of averaging per-second ratios", () => {
    // 1 of 1 in one second, 0 of 99 in the next: 1 percent, not the mean of 100 and 0.
    expect(windowRatio(historyOf([dns(1, 0), dns(0, 99)]), "dns-cache")).toBeCloseTo(1, 10);
  });

  it("is absent while no query fell in the window and present when one did, however quiet the rest", () => {
    expect(windowRatio(emptyHistory(), "dns-cache")).toBeNull();
    expect(windowRatio(historyOf([dns(0, 0), null, dns(0, 0)]), "dns-cache")).toBeNull();
    expect(windowRatio(historyOf([dns(2, 2), ...quiet(29)]), "dns-cache")).toBe(50);
    expect(windowRatio(historyOf([dns(2, 2), ...quiet(30)]), "dns-cache")).toBeNull();
  });

  it("looks at the last 30 samples only", () => {
    const h = historyOf([dns(0, 100), ...Array.from({ length: 30 }, () => dns(3, 1))]);
    expect(windowRatio(h, "dns-cache")).toBe(75);
  });

  it("gives the NOERROR share of all response codes for the answers tile", () => {
    expect(windowRatio(historyOf([dns(0, 0, 3, 1), dns(0, 0), dns(0, 0, 1, 3)]), "dns-answers")).toBe(50);
    expect(windowRatio(historyOf([dns(5, 5)]), "dns-answers")).toBeNull();
  });
});

describe("ratioBuckets", () => {
  it("is all empty without samples", () => {
    expect(ratioBuckets(emptyHistory(), 5, 12)).toEqual(Array(12).fill(null));
  });

  it("makes twelve buckets of five seconds, the newest ending at the newest sample", () => {
    // 60 samples: the oldest bucket only misses, then idle, the newest bucket 4 of 5 queries hit.
    const parts = Array.from({ length: 60 }, (_, i) => (i < 5 ? dns(0, 2) : i >= 55 ? dns(0.8, 0.2) : dns(0, 0)));
    const buckets = ratioBuckets(historyOf(parts), 5, 12);
    expect(buckets).toHaveLength(12);
    expect(buckets[0]).toBe(0);
    expect(buckets.slice(1, 11)).toEqual(Array(10).fill(null));
    expect(buckets[11]).toBeCloseTo(0.8, 10);
  });

  it("computes each bucket from sums and leaves the early buckets empty while the history is short", () => {
    // 7 samples: the newest bucket holds the last 5, the one before it the first 2.
    const parts = [dns(1, 0), dns(0, 1), dns(1, 0), dns(0, 3), dns(0, 3), dns(0, 3), dns(0, 3)];
    const buckets = ratioBuckets(historyOf(parts), 5, 12);
    expect(buckets.slice(0, 10)).toEqual(Array(10).fill(null));
    expect(buckets[10]).toBe(0.5);
    expect(buckets[11]).toBeCloseTo(1 / 13, 10);
  });

  it("follows the answers tile when asked", () => {
    const buckets = ratioBuckets(historyOf([dns(0, 0, 3, 1)]), 5, 12, "dns-answers");
    expect(buckets[11]).toBe(0.75);
    expect(buckets[10]).toBeNull();
  });
});
