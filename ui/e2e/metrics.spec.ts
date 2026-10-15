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
//
// Not covered here: a cluster of several controllers (the samples of the peers come through
// `Metrics.Snapshot`, which the Rust tests cover), and the CPU cost of 100 streams (the
// acceptance test `crates/tenko-api/tests/metrics_stream.rs`).

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

const TILES = ["requests", "commit", "store", "raft", "jobs", "ingest", "sse", "nodes"];

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

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the live metrics in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await openWithSample(page);
    await expectRendered(page, page.getByTestId("metrics-tiles"), "sv", testInfo, "metrics");
  });
});
