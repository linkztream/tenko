// WP3.5b: the live metrics of the start page (OPS-20, docs/observability.md section
// "Dashboard") against the real server.
//
// Scenarios:
// - An administrator sees the tiles below the start page's tiles; a sample of the `metrics`
//   topic arrives within three seconds and every tile carries a number; the Raft tile shows
//   this controller as the leader of a single-member cluster; the next samples keep coming.
// - A viewer does not see the tiles.
// - The tiles hold nothing to focus (the keyboard passes them by) and axe finds nothing.
// - Swedish.
// - WP3.8a, a cluster of several controllers: the e2e server is one controller, so these scenarios
//   FAKE THE METRICS STREAM. The request for the `metrics` topic is answered in the browser with
//   snapshots shaped like the server's (`MetricsSnapshot` of docs/api/openapi.json: the cluster's
//   sample and one sample per controller), and the later reconnects are refused. What they prove
//   is how the tiles show what they are given: the cluster's figures on every tile, one row per
//   controller with its role, its lag and its state (current, stale, unsupported), a sparkline
//   that grows with each sample, and the waiting state while nothing arrives. The samples of the
//   peers themselves come through `Metrics.Snapshot`, which the Rust tests cover.
// - WP5.6, the DNS tiles: the e2e server does not run the `dns` role, so its samples have no
//   `dns` part and the DNS tiles stay away; the faked stream carries one (the leader answers
//   queries) and the DNS tiles follow the others with the cluster's figures: queries with
//   p50 and p99, the cache hit ratio, the RCODE mix, the three busiest block lists, the
//   upstreams and the encrypted connections. The figures themselves come from the registry
//   (crates/tenko-api/src/sse/metrics/sample.rs and the `serve::metrics` tests).
//
// Not covered here: the CPU cost of 100 streams (the acceptance test
// `crates/tenko-api/tests/metrics_stream.rs`).

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { dnsPart, fakeMetricsStream, refuseMetricsStream, sample, type MetricsSnapshot } from "./support/metrics-mock";

const TILES = ["requests", "commit", "store", "raft", "jobs", "ingest", "sse", "nodes"];
const DNS_TILES = ["dns-queries", "dns-cache", "dns-answers", "dns-blocked", "dns-upstreams", "dns-encrypted"];

/** Opens the start page and waits until the tiles show their first sample. */
async function openWithSample(page: Page): Promise<void> {
  await page.goto("/");
  const tiles = page.getByTestId("metrics-tiles");
  await expect(tiles).toBeVisible();
  // One sample per second while the page listens; the first within three seconds.
  await expect(tiles).toHaveAttribute("data-controllers", "1", { timeout: 3_000 });
}

test("an administrator sees the live metrics, with a new sample every second", async ({ page, signedIn }) => {
  void signedIn;
  await openWithSample(page);
  await expect(page.getByTestId("metrics-waiting")).toHaveCount(0);
  for (const name of TILES) {
    const value = await page.getByTestId(`metrics-tile-${name}`).getAttribute("data-value");
    // The commit tile has no number in a second without writes; every other tile has one.
    if (name === "commit" && value === null) continue;
    expect(value, name).not.toBeNull();
    expect(Number.isFinite(Number(value)), `${name}: ${value}`).toBe(true);
    await expect(page.getByTestId(`metrics-sparkline-${name}`)).toBeAttached();
  }
  const row = page.getByTestId("metrics-raft-node");
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-role", "leader");
  await expect(row).toHaveAttribute("data-state", "current");
  // The e2e server runs the controller role only: no DNS tiles.
  for (const name of DNS_TILES) await expect(page.getByTestId(`metrics-tile-${name}`)).toHaveCount(0);
  // The page's own requests and the open stream show up in the figures.
  expect(Number(await page.getByTestId("metrics-tile-sse").getAttribute("data-value"))).toBeGreaterThanOrEqual(1);
  // More samples follow, one per second: the sparkline grows.
  const points = async () => Number(await page.getByTestId("metrics-sparkline-requests").getAttribute("data-points"));
  const before = await points();
  await expect.poll(points, { timeout: 5_000 }).toBeGreaterThanOrEqual(before + 2);
});

test("a viewer does not see the live metrics", async ({ page, api, signedIn }) => {
  void signedIn;
  await signInAsViewer(api);
  await page.goto("/");
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  await expect(page.getByTestId("dashboard-waiting")).toBeVisible();
  await expect(page.getByTestId("metrics-tiles")).toHaveCount(0);
});

/**
 * Runs axe-core in the page and answers the ids of the rules a part of it violates. The script is
 * evaluated through the browser's debugging protocol, since the page's CSP refuses injected tags.
 */
async function axeViolations(page: Page, selector: string): Promise<string[]> {
  await page.evaluate(await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8"));
  return page.evaluate(async (scope) => {
    const axe = (window as unknown as { axe: { run(context: string): Promise<{ violations: { id: string }[] }> } }).axe;
    return (await axe.run(scope)).violations.map((v) => v.id);
  }, selector);
}

test("the tiles hold nothing to focus and pass axe", async ({ page, signedIn }) => {
  void signedIn;
  await openWithSample(page);
  expect(await axeViolations(page, "[data-testid='metrics-tiles']")).toEqual([]);
  expect(await page.getByTestId("metrics-tiles").locator("svg[aria-hidden='true']").count()).toBe(TILES.length);
  // Tab through the page: the focus never lands inside the tiles, and it reaches the links of
  // the cards below them.
  await page.getByTestId("page-dashboard").click({ position: { x: 1, y: 1 } });
  let reachedBelow = false;
  for (let i = 0; i < 60 && !reachedBelow; i += 1) {
    await page.keyboard.press("Tab");
    const where = await page.evaluate(() => ({
      inTiles: !!document.activeElement?.closest("[data-testid='metrics-tiles']"),
      below: !!document.activeElement?.closest("[data-testid='dashboard-waiting'], [data-testid='dashboard-audit']"),
    }));
    expect(where.inTiles).toBe(false);
    reachedBelow = where.below;
  }
  expect(reachedBelow).toBe(true);
});

/**
 * Four controllers: 1 leads, 2 follows four entries behind, 3 did not answer this second (its last
 * good sample, stale) and 4 runs an older build without figures. The cluster sample sums the
 * controllers whose sample is current.
 */
function fourControllers(): MetricsSnapshot {
  const lag = [
    { node: 1, entries: 0 },
    { node: 2, entries: 4 },
  ];
  const leader = sample(1, {
    api: { requests_per_second: 20, p50_ms: 1.2, p99_ms: 30 },
    raft: { role: "leader", term: 9, lag },
    nodes: [{ node: 1001, buffer_batches: 5, drops: 0 }],
    dns: dnsPart(),
  });
  const follower = sample(2, {
    api: { requests_per_second: 15, p50_ms: 0.9, p99_ms: 18 },
    raft: { role: "follower", term: 9, lag: [{ node: 2, entries: 4 }] },
    nodes: [{ node: 1002, buffer_batches: 3, drops: 1 }],
  });
  const stale = sample(3, { stale: true, raft: { role: "follower", term: 9, lag: [] } });
  const unsupported = sample(4, { unsupported: true, raft: { role: null, term: 0, lag: [] } });
  const cluster = sample(null, {
    api: { requests_per_second: 35, p50_ms: 1.2, p99_ms: 30 },
    store: { data_bytes: 8_192, file_bytes: 4_000_000, commit_p99_ms: 6.4 },
    raft: { role: null, term: 9, lag },
    jobs: { running: 2, waiting: 1 },
    ingest: { batches_per_second: 1, facts_per_second: 25 },
    sse: { subscribers: 7 },
    nodes: [
      { node: 1001, buffer_batches: 5, drops: 0 },
      { node: 1002, buffer_batches: 3, drops: 1 },
    ],
    dns: dnsPart(),
  });
  return { cluster, nodes: [leader, follower, stale, unsupported] };
}

test("OPS-20: with several controllers the tiles show the cluster's figures and one row per controller (faked stream)", async ({ page, signedIn }) => {
  void signedIn;
  const base = fourControllers();
  // Three samples, the requests per second rising, so that the sparkline has three points.
  const rising = (rps: number): MetricsSnapshot => ({ ...base, cluster: { ...base.cluster, api: { ...base.cluster.api, requests_per_second: rps } } });
  await fakeMetricsStream(page, [rising(10), rising(20), base]);
  await page.goto("/");
  const tiles = page.getByTestId("metrics-tiles");
  await expect(tiles).toHaveAttribute("data-controllers", "4");
  await expect(page.getByTestId("metrics-waiting")).toHaveCount(0);

  // Every tile shows the cluster's sample of the last snapshot.
  const value = (name: string) => page.getByTestId(`metrics-tile-${name}`).getAttribute("data-value");
  expect(await value("requests")).toBe("35");
  expect(await value("commit")).toBe("6.4");
  expect(await value("store")).toBe("4000000");
  expect(await value("raft")).toBe("4");
  expect(await value("jobs")).toBe("2");
  expect(await value("ingest")).toBe("25");
  expect(await value("sse")).toBe("7");
  // The nodes tile is the batches buffered by the connected nodes of every controller.
  expect(await value("nodes")).toBe("8");
  await expect(page.getByTestId("metrics-sparkline-requests")).toHaveAttribute("data-points", "3");

  // One row per controller, with its role, its lag as the cluster reports it and its state.
  const rows = page.getByTestId("metrics-raft-node");
  await expect(rows).toHaveCount(4);
  const row = (node: number) => page.locator(`[data-testid="metrics-raft-node"][data-node="${node}"]`);
  await expect(row(1)).toHaveAttribute("data-role", "leader");
  await expect(row(1)).toHaveAttribute("data-state", "current");
  await expect(row(1)).toHaveAttribute("data-lag", "0");
  await expect(row(2)).toHaveAttribute("data-role", "follower");
  await expect(row(2)).toHaveAttribute("data-state", "current");
  await expect(row(2)).toHaveAttribute("data-lag", "4");
  // A controller that did not answer is marked stale and has no lag; one without figures is unsupported.
  await expect(row(3)).toHaveAttribute("data-state", "stale");
  await expect(row(3)).not.toHaveAttribute("data-lag", /.+/);
  await expect(row(4)).toHaveAttribute("data-state", "unsupported");
  await expect(row(4)).not.toHaveAttribute("data-role", /.+/);
  await expect(row(4)).not.toHaveAttribute("data-lag", /.+/);
});

test("OPS-20: a controller with the dns role adds the DNS tiles after the others (faked stream)", async ({ page, signedIn }) => {
  void signedIn;
  const base = fourControllers();
  const rising = (qps: number): MetricsSnapshot => ({ ...base, cluster: { ...base.cluster, dns: dnsPart({ queries_per_second: qps }) } });
  await fakeMetricsStream(page, [rising(800), rising(1_000), base]);
  await page.goto("/");
  await expect(page.getByTestId("metrics-tiles")).toHaveAttribute("data-controllers", "4");

  // The DNS tiles come after the Phase 1 tiles, in their order.
  const order = await page
    .getByTestId("metrics-tiles")
    .locator("[data-testid^='metrics-tile-']")
    .evaluateAll((tiles) => tiles.map((tile) => tile.getAttribute("data-testid")?.replace("metrics-tile-", "")));
  expect(order).toEqual([...TILES, ...DNS_TILES]);

  const tile = (name: string) => page.getByTestId(`metrics-tile-${name}`);
  await expect(tile("dns-queries")).toHaveAttribute("data-value", "1250");
  await expect(tile("dns-queries")).toContainText("p50 0.3 ms, p99 18 ms");
  await expect(page.getByTestId("metrics-sparkline-dns-queries")).toHaveAttribute("data-points", "3");
  await expect(tile("dns-cache")).toHaveAttribute("data-value", "82");
  await expect(tile("dns-cache")).toContainText("8.4K entries");
  // The answers: the NOERROR share and one row per RCODE.
  await expect(tile("dns-answers")).toHaveAttribute("data-value", "80");
  await expect(tile("dns-answers").getByTestId("metrics-dns-rcode")).toHaveCount(5);
  await expect(tile("dns-answers").locator("[data-rcode='servfail']")).toHaveAttribute("data-rate", "50");
  // The blocked queries over every list, and the three busiest lists.
  await expect(tile("dns-blocked")).toHaveAttribute("data-value", "49");
  const lists = tile("dns-blocked").getByTestId("metrics-dns-list");
  await expect(lists).toHaveCount(3);
  expect(await lists.evaluateAll((rows) => rows.map((row) => row.getAttribute("data-list")))).toEqual(["ads", "trackers", "telemetry"]);
  await expect(tile("dns-upstreams")).toHaveAttribute("data-value", "90");
  await expect(tile("dns-upstreams")).toContainText("p99 42 ms");
  await expect(tile("dns-encrypted")).toHaveAttribute("data-value", "9");
  await expect(tile("dns-encrypted")).toContainText("DoT 6, DoH 3");
  expect(await axeViolations(page, "[data-testid='metrics-tiles']")).toEqual([]);
});

test("OPS-20: while no sample arrives the tiles say they are waiting and show no number (faked stream)", async ({ page, signedIn }) => {
  void signedIn;
  await refuseMetricsStream(page);
  await page.goto("/");
  const tiles = page.getByTestId("metrics-tiles");
  await expect(tiles).toBeVisible();
  await expect(page.getByTestId("metrics-waiting")).toBeVisible();
  await expect(tiles).not.toHaveAttribute("data-controllers", /.+/);
  for (const name of TILES) await expect(page.getByTestId(`metrics-tile-${name}`)).not.toHaveAttribute("data-value", /.+/);
  await expect(page.getByTestId("metrics-raft-node")).toHaveCount(0);
  // The rest of the start page does not wait for them.
  await expect(page.getByTestId("dashboard-waiting")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("OPS-20: renders the rows of a stale and an unsupported controller in Swedish (faked stream)", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await fakeMetricsStream(page, [fourControllers()]);
    await page.goto("/");
    await expect(page.getByTestId("metrics-tiles")).toHaveAttribute("data-controllers", "4");
    await expectRendered(page, page.getByTestId("metrics-tiles"), "sv", testInfo, "metrics-cluster");
  });

  test("renders the live metrics in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await openWithSample(page);
    await expectRendered(page, page.getByTestId("metrics-tiles"), "sv", testInfo, "metrics");
  });
});
