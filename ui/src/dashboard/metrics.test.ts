import { describe, expect, it } from "vitest";
import {
  emptyHistory,
  GIB,
  HOST_TILES,
  memoryPercent,
  memoryUsed,
  pushSnapshot,
  ratioBuckets,
  RCODES,
  RECURSION_TILES,
  tileValue,
  VALIDATION_STATES,
  windowRate,
  windowRatio,
  type MetricsDns,
  type MetricsHistory,
  type MetricsHost,
  type MetricsSample,
} from "./metrics";

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

/** 2026-10-14T12:00:00Z, a multiple of every bucket length; the tests count seconds from it. */
const T0 = Date.parse("2026-10-14T12:00:00Z");
const clock = (seconds: number) => new Date(T0 + seconds * 1000).toISOString();

function sample(part: MetricsDns | null, seconds = 0): MetricsSample {
  return {
    node: null,
    at: clock(seconds),
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

/** A history of one sample per second from second `from`, the parts in order. */
function historyOf(parts: (MetricsDns | null)[], from = 0): MetricsHistory {
  return parts.reduce((h, part, i) => pushSnapshot(h, { nodes: [], cluster: sample(part, from + i) }), emptyHistory());
}

/** A history with samples at the given seconds (fractions allowed), oldest first. */
function historyAt(entries: readonly (readonly [number, MetricsDns | null])[]): MetricsHistory {
  return entries.reduce((h, [seconds, part]) => pushSnapshot(h, { nodes: [], cluster: sample(part, seconds) }), emptyHistory());
}

const quiet = (n: number) => Array.from({ length: n }, () => dns(0, 0));

describe("windowRatio", () => {
  it("sums hits and misses over the window instead of averaging per-second ratios", () => {
    // 1 of 1 in one second, 0 of 99 in the next, both in a bucket that has completed: 1 percent, not the mean of 100 and 0.
    expect(windowRatio(historyAt([[0, dns(1, 0)], [1, dns(0, 99)], [5, dns(0, 0)]]), "dns-cache")).toBeCloseTo(1, 10);
  });

  it("takes the bucket in progress while no bucket has completed (the page just opened)", () => {
    expect(windowRatio(historyOf([dns(1, 0), dns(0, 99)]), "dns-cache")).toBeCloseTo(1, 10);
  });

  it("is absent while no query fell in the window and present when one did, however quiet the rest", () => {
    expect(windowRatio(emptyHistory(), "dns-cache")).toBeNull();
    expect(windowRatio(historyOf([dns(0, 0), null, dns(0, 0)]), "dns-cache")).toBeNull();
    // Seconds 0 to 34: the newest bucket is the seventh, the first is still among the six completed ones.
    expect(windowRatio(historyOf([dns(2, 2), ...quiet(34)]), "dns-cache")).toBe(50);
    // Second 35 opens the eighth bucket: the first leaves the window.
    expect(windowRatio(historyOf([dns(2, 2), ...quiet(35)]), "dns-cache")).toBeNull();
  });

  it("moves only when a bucket completes, not with every sample", () => {
    const base = [...Array.from({ length: 5 }, () => dns(1, 0)), dns(0, 1), dns(0, 1), dns(0, 1)];
    // Seconds 0 to 7: bucket 0 is complete (5 hits), bucket 1 is in progress and not counted.
    expect(windowRatio(historyOf(base), "dns-cache")).toBe(100);
    expect(windowRatio(historyOf([...base, dns(0, 9)]), "dns-cache")).toBe(100);
    // Second 10 opens bucket 2: buckets 0 and 1 count, 5 hits of 8.
    expect(windowRatio(historyOf([...base, dns(0, 0), dns(0, 0), dns(0, 0)]), "dns-cache")).toBe(62.5);
  });

  it("is empty after a gap of more than the window", () => {
    expect(windowRatio(historyAt([[0, dns(2, 2)], [40, dns(0, 0)]]), "dns-cache")).toBeNull();
  });

  it("gives the NOERROR share of all response codes for the answers tile", () => {
    expect(windowRatio(historyOf([dns(0, 0, 3, 1), dns(0, 0), dns(0, 0, 1, 3)]), "dns-answers")).toBe(50);
    expect(windowRatio(historyOf([dns(5, 5)]), "dns-answers")).toBeNull();
  });
});

describe("ratioBuckets", () => {
  const SEVEN = 7;
  const bars = (h: MetricsHistory, tile: "dns-cache" | "dns-answers" = "dns-cache") => ratioBuckets(h, 5, SEVEN, tile);
  // The bucket 0 (seconds 0 to 4) only misses, the bucket 2 (10 to 14) half hits, the newest, bucket 6 (30 to 34), 4 of 5.
  const base = [
    [0, dns(0, 2)],
    [12, dns(1, 1)],
    [31, dns(0.8, 0.2)],
  ] as const;

  it("is all empty without samples", () => {
    expect(bars(emptyHistory())).toEqual(Array(SEVEN).fill(null));
  });

  it("puts samples at known seconds into the bars of their own buckets, the newest last", () => {
    const out = bars(historyAt(base));
    expect(out).toHaveLength(SEVEN);
    expect(out[0]).toBe(0);
    expect(out.slice(1, 6)).toEqual([null, 0.5, null, null, null]);
    expect(out[6]).toBeCloseTo(0.8, 10);
  });

  it("sums a bucket's samples instead of averaging their shares", () => {
    // 1 of 1 then 0 of 3 in the same bucket is a quarter, not the mean of 1 and 0.
    const out = bars(historyAt([[30, dns(1, 0)], [31, dns(0, 3)]]));
    expect(out.slice(0, 6)).toEqual(Array(6).fill(null));
    expect(out[6]).toBe(0.25);
  });

  it("changes only the last bar when a sample falls inside the bucket in progress", () => {
    const before = bars(historyAt(base));
    const after = bars(historyAt([...base, [33, dns(0, 1)]]));
    expect(after.slice(0, 6)).toEqual(before.slice(0, 6));
    expect(after[6]).toBeCloseTo(0.8 / 2, 10);
    // And a tick every second for the whole bucket never moves the older bars.
    let h = historyAt(base);
    for (let s = 32; s < 35; s++) {
      h = pushSnapshot(h, { nodes: [], cluster: sample(dns(0, 1), s) });
      expect(bars(h).slice(0, 6)).toEqual(before.slice(0, 6));
    }
  });

  it("shifts by exactly one step when a sample of the next bucket arrives", () => {
    const before = bars(historyAt(base));
    const after = bars(historyAt([...base, [33, dns(0, 1)], [35, dns(1, 1)]]));
    // The bar in progress became a completed bar (with the sample of second 33 in it) and a new bar was born.
    expect(after.slice(0, 5)).toEqual(before.slice(1, 6));
    expect(after[5]).toBeCloseTo(0.4, 10);
    expect(after[6]).toBe(0.5);
  });

  it("puts a sample in the bucket of its own time however the samples are spaced", () => {
    // 4.999 s and 5.000 s are a bucket apart; 0.4 s and 4.9 s are not.
    const out = bars(historyAt([[0.4, dns(1, 0)], [4.9, dns(1, 0)], [4.999, dns(1, 0)], [5, dns(0, 1)]]));
    expect(out.slice(0, 5)).toEqual(Array(5).fill(null));
    expect(out[5]).toBe(1);
    expect(out[6]).toBe(0);
  });

  it("empties the ring after a gap of more than the 30 seconds it holds", () => {
    const out = bars(historyAt([...base, [75, dns(0, 1)]]));
    expect(out.slice(0, 6)).toEqual(Array(6).fill(null));
    expect(out[6]).toBe(0);
  });

  it("ignores a sample from a later bucket than the newest (the clock stepped back)", () => {
    const out = bars(historyAt([[100, dns(1, 0)], [50, dns(0, 1)]]));
    expect(out.slice(0, 6)).toEqual(Array(6).fill(null));
    expect(out[6]).toBe(0);
  });

  it("follows the answers tile when asked", () => {
    const out = bars(historyAt([[0, dns(0, 0, 3, 1)]]), "dns-answers");
    expect(out[6]).toBe(0.75);
    expect(out[5]).toBeNull();
  });
});

describe("the figures beside the bars", () => {
  // One NOERROR answer in the first bucket and one NXDOMAIN in the second: every sample's own rate is
  // zero but two, and the newest second reads zero.
  const sparse = historyOf(
    Array.from({ length: 12 }, (_, s) => (s === 2 ? dns(0, 0, 1, 0) : s === 7 ? dns(0, 0, 0, 1) : dns(0, 0))),
  );

  it("agree: the mean rates are the counts of the samples behind the headline and the bars", () => {
    expect(sparse.cluster[sparse.cluster.length - 1]?.dns?.rcodes.noerror).toBe(0);
    // The window is seconds 0 to 9 (buckets 0 and 1 completed, bucket 2 in progress).
    expect(windowRate(sparse, (d) => d.rcodes.noerror)).toBeCloseTo(0.1, 10);
    expect(windowRate(sparse, (d) => d.rcodes.nxdomain)).toBeCloseTo(0.1, 10);
    expect(windowRate(sparse, (d) => d.rcodes.servfail)).toBe(0);
    expect(windowRatio(sparse, "dns-answers")).toBe(50);
    // The share of the headline is the share of the rates...
    const noerror = windowRate(sparse, (d) => d.rcodes.noerror)!;
    const all = RCODES.reduce((sum, code) => sum + windowRate(sparse, (d) => d.rcodes[code])!, 0);
    expect((noerror * 100) / all).toBeCloseTo(windowRatio(sparse, "dns-answers")!, 10);
    // ... and the bars before the one in progress are the shares of the buckets the rates are made of.
    expect(ratioBuckets(sparse, 5, 7, "dns-answers").slice(5)).toEqual([0, null]);
    expect(ratioBuckets(sparse, 5, 7, "dns-answers")[4]).toBe(1);
  });

  it("move with the headline, once per bucket, not with every sample", () => {
    const next = pushSnapshot(sparse, { nodes: [], cluster: sample(dns(0, 0, 4, 0), 12) });
    expect(windowRate(next, (d) => d.rcodes.noerror)).toBe(windowRate(sparse, (d) => d.rcodes.noerror));
    const later = pushSnapshot(next, { nodes: [], cluster: sample(dns(0, 0), 15) });
    expect(windowRate(later, (d) => d.rcodes.noerror)).toBeCloseTo((1 + 4) / 13, 10);
  });

  it("weigh a sample by the seconds it spans", () => {
    const slow = { ...sample(dns(0, 0, 3, 0), 0), interval_ms: 3000 };
    const fast = { ...sample(dns(0, 0, 0, 0), 4), interval_ms: 1000 };
    const h = [slow, fast, sample(dns(0, 0), 5)].reduce((acc, s) => pushSnapshot(acc, { nodes: [], cluster: s }), emptyHistory());
    // 9 answers in the 3 seconds, 0 in the next second: 9 over 4 seconds.
    expect(windowRate(h, (d) => d.rcodes.noerror)).toBeCloseTo(9 / 4, 10);
  });

  it("are absent without a dns sample", () => {
    expect(windowRate(emptyHistory(), (d) => d.rcodes.noerror)).toBeNull();
    expect(windowRate(historyOf([null, null]), (d) => d.rcodes.noerror)).toBeNull();
  });
});

// WP10.4: the tiles of the recursive resolver.
describe("tileValue of the recursion tiles", () => {
  const recursion = { subqueries_per_second: 320, validation: { secure: 48, insecure: 31, bogus: 0.5, indeterminate: 1.25 } };

  it("names the two tiles and the three outcomes the validation tile lists", () => {
    expect([...RECURSION_TILES]).toEqual(["dns-subqueries", "dns-validation"]);
    expect([...VALIDATION_STATES]).toEqual(["secure", "insecure", "bogus"]);
  });

  it("gives the sub-queries per second as they are", () => {
    expect(tileValue("dns-subqueries", sample({ ...dns(0, 0), recursion }))).toBe(320);
    expect(tileValue("dns-subqueries", sample({ ...dns(0, 0), recursion: { ...recursion, subqueries_per_second: 0 } }))).toBe(0);
  });

  it("gives the validation tile the sum of all four outcomes, the indeterminate ones included", () => {
    expect(tileValue("dns-validation", sample({ ...dns(0, 0), recursion }))).toBe(80.75);
    expect(tileValue("dns-validation", sample({ ...dns(0, 0), recursion: { ...recursion, validation: { secure: 0, insecure: 0, bogus: 0, indeterminate: 3 } } }))).toBe(3);
    expect(tileValue("dns-validation", sample({ ...dns(0, 0), recursion: { ...recursion, validation: { secure: 0, insecure: 0, bogus: 0, indeterminate: 0 } } }))).toBe(0);
  });

  it("gives nothing without the resolver, without a DNS part or without a sample", () => {
    expect(tileValue("dns-subqueries", sample(dns(1, 1)))).toBeNull();
    expect(tileValue("dns-validation", sample(dns(1, 1)))).toBeNull();
    expect(tileValue("dns-subqueries", sample({ ...dns(1, 1), recursion: null }))).toBeNull();
    expect(tileValue("dns-validation", sample({ ...dns(1, 1), recursion: null }))).toBeNull();
    expect(tileValue("dns-subqueries", sample(null))).toBeNull();
    expect(tileValue("dns-validation", sample(null))).toBeNull();
  });

  it("leaves the other DNS tiles to their own values", () => {
    const part = { ...dns(3, 1, 4, 0), recursion };
    expect(tileValue("dns-queries", sample(part))).toBe(4);
    expect(tileValue("dns-cache", sample(part))).toBe(75);
    expect(tileValue("dns-upstreams", sample(part))).toBe(0);
  });
});

// OPS-20: the tiles of the host.
describe("tileValue of the host tiles", () => {
  const host: MetricsHost = {
    cpu_percent: 37.5,
    memory_total: 16 * GIB,
    memory_available: 4 * GIB,
    disk_total: 512 * GIB,
    disk_available: 128 * GIB,
  };
  const withHost = (part: MetricsHost | null): MetricsSample => ({ ...sample(null), host: part });

  it("names the three tiles", () => {
    expect([...HOST_TILES]).toEqual(["host-cpu", "host-memory", "host-disk"]);
  });

  it("gives the CPU share, the memory in use as a share and the disk space available in GiB", () => {
    expect(tileValue("host-cpu", withHost(host))).toBe(37.5);
    expect(tileValue("host-memory", withHost(host))).toBe(75);
    expect(tileValue("host-disk", withHost(host))).toBe(128);
    expect(memoryUsed(host)).toBe(12 * GIB);
    expect(memoryPercent(host)).toBe(75);
  });

  it("gives nothing for a figure the node did not read, and nothing without a host part", () => {
    const windows: MetricsHost = { disk_total: 100 * GIB, disk_available: 50 * GIB };
    expect(tileValue("host-cpu", withHost(windows))).toBeNull();
    expect(tileValue("host-memory", withHost(windows))).toBeNull();
    expect(tileValue("host-disk", withHost(windows))).toBe(50);
    expect(memoryUsed(windows)).toBeNull();
    expect(tileValue("host-disk", withHost({ cpu_percent: 1 }))).toBeNull();
    for (const name of HOST_TILES) {
      expect(tileValue(name, withHost(null))).toBeNull();
      expect(tileValue(name, sample(null))).toBeNull();
    }
  });

  it("never reports a negative memory use or divides by a zero total", () => {
    expect(memoryUsed({ memory_total: 4, memory_available: 9 })).toBe(0);
    expect(memoryPercent({ memory_total: 0, memory_available: 0 })).toBeNull();
  });
});
