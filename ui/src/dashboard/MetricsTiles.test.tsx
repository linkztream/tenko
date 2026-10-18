import { render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { setLocale } from "../i18n";
import type { MetricsDns, MetricsSample, MetricsSnapshot } from "./metrics";
import MetricsTiles from "./MetricsTiles";

/** A stand-in for EventSource that the tests feed. */
class FakeSource {
  static all: FakeSource[] = [];
  readonly url: string;
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  closed = false;
  private listeners = new Map<string, ((e: Event) => void)[]>();

  constructor(url: string) {
    this.url = url;
    FakeSource.all.push(this);
  }
  addEventListener(type: string, fn: (e: Event) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  close() {
    this.closed = true;
  }
  open() {
    this.onopen?.(new Event("open"));
  }
  emit(type: string, data: unknown) {
    const event = new MessageEvent(type, { data: JSON.stringify(data) });
    for (const fn of this.listeners.get(type) ?? []) fn(event);
  }
  static last(): FakeSource {
    const source = FakeSource.all[FakeSource.all.length - 1];
    if (!source) throw new Error("no stream");
    return source;
  }
}

function sample(node: number | null, patch: Partial<MetricsSample> = {}): MetricsSample {
  return {
    node,
    at: "2026-10-14T12:00:00Z",
    interval_ms: 1000,
    api: { requests_per_second: 12.5, p50_ms: 0.8, p99_ms: 24 },
    store: { data_bytes: 4_096, file_bytes: 1_500_000, commit_p99_ms: 3.2 },
    raft: { role: node === null ? null : "leader", term: 3, lag: [{ node: node ?? 1, entries: 0 }] },
    jobs: { running: 2, waiting: 1 },
    ingest: { batches_per_second: 0.5, facts_per_second: 40 },
    sse: { subscribers: 4 },
    nodes: [{ node: 1001, buffer_batches: 7, drops: 2 }],
    ...patch,
  };
}

function snapshot(nodes: MetricsSample[], cluster: MetricsSample): MetricsSnapshot {
  return { nodes, cluster };
}

function send(source: FakeSource, value: MetricsSnapshot) {
  source.emit("metrics", { topic: "metrics", kind: "metrics.snapshot", metrics: value });
}

function mount() {
  return render(() => <MetricsTiles streamOptions={{ createEventSource: (url) => new FakeSource(url) as unknown as EventSource }} />);
}

const tile = (name: string) => screen.getByTestId(`metrics-tile-${name}`);

beforeEach(async () => {
  FakeSource.all = [];
  await setLocale("en");
});

afterEach(async () => {
  await setLocale("en");
});

describe("metrics tiles", () => {
  it("open a stream of their own on the metrics topic and close it when the page goes", async () => {
    const { unmount } = mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    const url = new URL(source.url, "http://localhost");
    expect(url.pathname).toBe("/api/v1/events");
    expect(url.searchParams.get("topics")).toBe("metrics");
    expect(screen.getByTestId("metrics-tiles").dataset.state).toBe("connecting");
    source.open();
    await waitFor(() => expect(screen.getByTestId("metrics-tiles").dataset.state).toBe("live"));
    expect(screen.getByTestId("metrics-waiting")).toBeTruthy();
    expect(tile("requests").dataset.value).toBeUndefined();
    unmount();
    expect(source.closed).toBe(true);
  });

  it("show the numbers of the newest sample and a sparkline of every sample", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    source.open();
    for (const rate of [10, 20, 30]) {
      const own = sample(1, { api: { requests_per_second: rate, p50_ms: 0.8, p99_ms: 24 } });
      send(source, snapshot([own], { ...own, node: null, raft: { ...own.raft, role: null } }));
    }
    await waitFor(() => expect(tile("requests").dataset.value).toBe("30"));
    expect(screen.queryByTestId("metrics-waiting")).toBeNull();
    expect(screen.getByTestId("metrics-tiles").dataset.controllers).toBe("1");
    expect(screen.getByTestId("metrics-sparkline-requests").dataset.points).toBe("3");
    expect(screen.getByTestId("metrics-sparkline-requests").querySelector("title")?.textContent).toBe(
      "API requests over the last minute: 10, 20, 30",
    );
    expect(tile("requests").textContent).toContain("p50 0.8 ms, p99 24 ms");
    expect(tile("commit").dataset.value).toBe("3.2");
    expect(tile("store").dataset.value).toBe("1500000");
    expect(tile("store").textContent).toContain("1.5M");
    expect(tile("store").textContent).toContain("4.1KB of live data in memory");
    expect(tile("raft").dataset.value).toBe("0");
    expect(tile("jobs").dataset.value).toBe("2");
    expect(tile("jobs").textContent).toContain("1 job waiting");
    expect(tile("ingest").dataset.value).toBe("40");
    expect(tile("ingest").textContent).toContain("0.5 batches per second");
    expect(tile("sse").dataset.value).toBe("4");
    expect(tile("nodes").dataset.value).toBe("7");
    expect(tile("nodes").textContent).toContain("1 node connected, 2 batches dropped");
    const rows = within(tile("raft")).getAllByTestId("metrics-raft-node");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.dataset).toMatchObject({ node: "1", role: "leader", lag: "0", state: "current" });
    expect(await axeViolations(screen.getByTestId("metrics-tiles"))).toEqual([]);
  });

  it("show a minute: the sixty newest samples", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    for (let i = 1; i <= 65; i++) {
      const own = sample(1, { sse: { subscribers: i } });
      send(source, snapshot([own], own));
    }
    await waitFor(() => expect(tile("sse").dataset.value).toBe("65"));
    expect(screen.getByTestId("metrics-sparkline-sse").dataset.points).toBe("60");
  });

  it("show the cluster's sum and one Raft row per controller, marking silent and older ones", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    const leader = sample(1, {
      raft: {
        role: "leader",
        term: 5,
        lag: [
          { node: 1, entries: 0 },
          { node: 2, entries: 12 },
          { node: 3, entries: 3 },
        ],
      },
    });
    const silent = { ...sample(2, { raft: { role: "follower", term: 5, lag: [{ node: 2, entries: 9 }] } }), stale: true };
    const older = { ...sample(3, { raft: { role: null, term: 0, lag: [] } }), unsupported: true };
    const cluster = sample(null, {
      api: { requests_per_second: 99, p50_ms: 1, p99_ms: 40 },
      raft: { role: null, term: 5, lag: leader.raft.lag },
    });
    send(source, snapshot([leader, silent, older], cluster));
    await waitFor(() => expect(tile("requests").dataset.value).toBe("99"));
    expect(screen.getByTestId("metrics-tiles").dataset.controllers).toBe("3");
    expect(tile("raft").dataset.value).toBe("12");
    const rows = within(tile("raft")).getAllByTestId("metrics-raft-node");
    expect(rows.map((row) => ({ ...row.dataset }))).toEqual([
      { testid: "metrics-raft-node", node: "1", role: "leader", lag: "0", state: "current" },
      { testid: "metrics-raft-node", node: "2", role: "follower", lag: "12", state: "stale" },
      { testid: "metrics-raft-node", node: "3", lag: "3", state: "unsupported" },
    ]);
    expect(rows[1]!.textContent).toContain("No answer");
    expect(rows[2]!.textContent).toContain("Older version");
    expect(rows[1]!.textContent).toContain("12 entries behind");
    expect(await axeViolations(screen.getByTestId("metrics-tiles"))).toEqual([]);
  });

  it("ignore other events and show an idle API and an in-memory store in words", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    source.emit("metrics", { topic: "metrics", kind: "something.else", metrics: {} });
    source.emit("metrics", { topic: "metrics", kind: "metrics.snapshot" });
    expect(screen.getByTestId("metrics-waiting")).toBeTruthy();
    const idle = sample(1, {
      api: { requests_per_second: 0 },
      store: { data_bytes: 2_048 },
      nodes: [{ node: 1001, buffer_batches: 0 }],
    });
    send(source, snapshot([idle], idle));
    await waitFor(() => expect(tile("requests").dataset.value).toBe("0"));
    expect(tile("requests").textContent).toContain("No requests in the last second");
    expect(tile("commit").dataset.value).toBeUndefined();
    expect(tile("commit").textContent).toContain("No writes in the last second");
    expect(tile("store").dataset.value).toBe("2048");
    expect(tile("store").textContent).toContain("In memory only, nothing on disk");
    expect(tile("nodes").textContent).toContain("1 node connected");
    expect(tile("nodes").textContent).not.toContain("dropped");
  });

  it("speak Swedish", async () => {
    await setLocale("sv");
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const own = sample(1);
    send(FakeSource.last(), snapshot([own], own));
    await waitFor(() => expect(tile("jobs").dataset.value).toBe("2"));
    const root = screen.getByTestId("metrics-tiles");
    expect(root.textContent).toContain("Mätvärden i realtid");
    expect(tile("jobs").textContent).toContain("1 jobb väntar");
    expect(tile("nodes").textContent).toContain("1 nod ansluten, 2 omgångar kastade");
    expect(within(tile("raft")).getByTestId("metrics-raft-node").textContent).toContain("ledare");
  });
});

function dnsPart(patch: Partial<MetricsDns> = {}): MetricsDns {
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
      { list: "quiet", per_second: 0 },
    ],
    connections: { dot: 6, doh: 3 },
    log_dropped_per_second: 0,
    ...patch,
  };
}

const DNS_TILES = ["dns-queries", "dns-cache", "dns-answers", "dns-blocked", "dns-upstreams", "dns-encrypted"];

describe("DNS tiles", () => {
  it("are not shown while no controller runs the dns role", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const own = sample(1);
    send(FakeSource.last(), snapshot([own], own));
    await waitFor(() => expect(tile("requests").dataset.value).toBe("12.5"));
    for (const name of DNS_TILES) expect(screen.queryByTestId(`metrics-tile-${name}`)).toBeNull();
  });

  it("follow the other tiles with the queries, the cache, the answers, the lists, the upstreams and the connections", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    for (const qps of [900, 1_100, 1_250]) {
      const own = sample(1, { dns: dnsPart({ queries_per_second: qps }) });
      send(source, snapshot([own], own));
    }
    await waitFor(() => expect(tile("dns-queries").dataset.value).toBe("1250"));
    expect([...screen.getByTestId("metrics-tiles").querySelectorAll("[data-testid^='metrics-tile-']")].map((el) => el.getAttribute("data-testid"))).toEqual(
      ["requests", "commit", "store", "raft", "jobs", "ingest", "sse", "nodes", ...DNS_TILES].map((name) => `metrics-tile-${name}`),
    );
    expect(tile("dns-queries").textContent).toContain("1.3K");
    expect(tile("dns-queries").textContent).toContain("p50 0.3 ms, p99 18 ms");
    expect(screen.getByTestId("metrics-sparkline-dns-queries").dataset.points).toBe("3");
    expect(screen.getByTestId("metrics-dns-log-dropped").dataset.state).toBe("idle");
    expect(screen.getByTestId("metrics-dns-log-dropped").textContent).toBe("");
    expect(tile("dns-cache").dataset.value).toBe("82");
    expect(tile("dns-cache").textContent).toContain("8.4K entries, 1.5 stale/s");
    expect(tile("dns-cache").textContent).toContain("Last 30 s; bars per 5 s");
    expect(within(tile("dns-cache")).queryByTestId("metrics-sparkline-dns-cache")).toBeNull();
    const bars = within(tile("dns-cache")).getByTestId("metrics-bars");
    expect(bars.getAttribute("data-buckets")).toBe("12");
    expect(bars.getAttribute("aria-hidden")).toBe("true");
    expect(bars.querySelectorAll("rect")).toHaveLength(1);
    expect(tile("dns-answers").textContent).toContain("NOERROR share, last 30 s; bars per 5 s");
    expect(within(tile("dns-answers")).getByTestId("metrics-bars").getAttribute("data-buckets")).toBe("12");
    expect(within(tile("dns-queries")).queryByTestId("metrics-bars")).toBeNull();
    expect(tile("dns-answers").dataset.value).toBe("80");
    const rcodes = within(tile("dns-answers")).getAllByTestId("metrics-dns-rcode");
    expect(rcodes.map((row) => [row.dataset.rcode, row.dataset.rate])).toEqual([
      ["noerror", "1000"],
      ["nxdomain", "150"],
      ["servfail", "50"],
      ["refused", "25"],
      ["other", "25"],
    ]);
    expect(rcodes[0]!.textContent).toBe("NOERROR1,000/s");
    expect(rcodes[4]!.textContent).toContain("Other");
    expect(tile("dns-blocked").dataset.value).toBe("49");
    expect(tile("dns-blocked").textContent).toContain("5 lists have blocked queries");
    const lists = within(tile("dns-blocked")).getAllByTestId("metrics-dns-list");
    expect(lists.map((row) => [row.dataset.list, row.dataset.rate])).toEqual([
      ["ads", "30"],
      ["trackers", "12"],
      ["telemetry", "5"],
    ]);
    expect(tile("dns-upstreams").dataset.value).toBe("90");
    expect(tile("dns-upstreams").textContent).toContain("Round trip p99 42 ms");
    expect(tile("dns-encrypted").dataset.value).toBe("9");
    expect(tile("dns-encrypted").textContent).toContain("DoT 6, DoH 3");
    expect(await axeViolations(screen.getByTestId("metrics-tiles"))).toEqual([]);
  });

  it("say when the role is idle, has no lists, serves no encrypted transport and drops log entries", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const idle = sample(1, {
      dns: dnsPart({
        queries_per_second: 0,
        transports: { udp: 0, tcp: 0, dot: 0, doh: 0 },
        p50_ms: null,
        p99_ms: null,
        rcodes: { noerror: 0, nxdomain: 0, servfail: 0, refused: 0, other: 0 },
        cache: { hit_ratio: null, hits_per_second: 0, misses_per_second: 0, stale_per_second: 0, entries: 0 },
        upstreams: { queries_per_second: 0 },
        blocked: [],
        connections: null,
        log_dropped_per_second: 3.5,
      }),
    });
    send(FakeSource.last(), snapshot([idle], idle));
    await waitFor(() => expect(tile("dns-queries").dataset.value).toBe("0"));
    expect(tile("dns-queries").textContent).toContain("No queries in the last second");
    expect(screen.getByTestId("metrics-dns-log-dropped").dataset.state).toBe("dropping");
    expect(screen.getByTestId("metrics-dns-log-dropped").textContent).toBe("3.5 query log entries dropped per second");
    expect(tile("dns-cache").dataset.value).toBeUndefined();
    expect(tile("dns-answers").dataset.value).toBeUndefined();
    expect(tile("dns-blocked").dataset.value).toBe("0");
    expect(tile("dns-blocked").textContent).toContain("No list has blocked a query");
    expect(within(tile("dns-blocked")).queryAllByTestId("metrics-dns-list")).toHaveLength(0);
    expect(tile("dns-upstreams").textContent).toContain("No upstream answered in the last second");
    expect(screen.queryByTestId("metrics-tile-dns-encrypted")).toBeNull();
  });

  it("show the share of the last 30 seconds, not of the newest second, and keep it through quiet seconds", async () => {
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.last();
    const cache = (hits: number, misses: number) => ({ hit_ratio: hits + misses > 0 ? hits / (hits + misses) : null, hits_per_second: hits, misses_per_second: misses, stale_per_second: 0, entries: 10 });
    const rcodes = (noerror: number, nxdomain: number) => ({ noerror, nxdomain, servfail: 0, refused: 0, other: 0 });
    for (const [hits, misses, ok, nx] of [[1, 0, 1, 0], [0, 3, 1, 2], [0, 0, 0, 0]] as const) {
      const own = sample(1, { dns: dnsPart({ cache: cache(hits, misses), rcodes: rcodes(ok, nx) }) });
      send(source, snapshot([own], own));
    }
    // The newest second is quiet, so its own ratio is absent, yet the window has queries: 1 hit of 4.
    await waitFor(() => expect(tile("dns-cache").dataset.value).toBe("25"));
    expect(tile("dns-answers").dataset.value).toBe("50");
    // The newest bucket holds all three samples: a bar of a quarter of the height.
    const [bar] = within(tile("dns-cache")).getByTestId("metrics-bars").querySelectorAll("rect");
    expect(bar?.getAttribute("height")).toBe("5");
  });

  it("speak Swedish", async () => {
    await setLocale("sv");
    mount();
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const own = sample(1, { dns: dnsPart({ log_dropped_per_second: 2 }) });
    send(FakeSource.last(), snapshot([own], own));
    await waitFor(() => expect(tile("dns-queries").dataset.value).toBe("1250"));
    expect(tile("dns-queries").textContent).toContain("DNS-frågor");
    expect(screen.getByTestId("metrics-dns-log-dropped").textContent).toContain("poster i frågeloggen kastade per sekund");
    expect(tile("dns-cache").textContent).toContain("Träffandel i cachen");
    expect(tile("dns-cache").textContent).toContain("Senaste 30 s; staplar per 5 s");
    expect(tile("dns-answers").textContent).toContain("Andel NOERROR, senaste 30 s; staplar per 5 s");
    expect(tile("dns-answers").textContent).toContain("Övriga");
    expect(tile("dns-blocked").textContent).toContain("5 listor har blockerat frågor");
    expect(tile("dns-upstreams").textContent).toContain("Svarstid p99 42 ms");
    expect(tile("dns-encrypted").textContent).toContain("Krypterade anslutningar");
  });
});
