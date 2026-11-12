// OPS-20: the history charts of the live metrics tiles (docs/plans/dashboard-history-plan.md,
// E117 and M85) against the real server, with the `metrics` stream FAKED in the browser.
//
// WHY THE STREAM IS FAKED: two days of history cannot be waited for in a test, so the request of
// the tiles for the `metrics` topic is answered with a `metrics.history` of every tile's figure
// (the deterministic TEST DATA of src/dashboard/historyTestData.ts, two days with every ring full)
// and one snapshot, both at the moment of the request. The stream then ends and the page opens it
// again about a second later, as after a dropped connection, and gets the next history: so the
// controller's clock moves on and the charts glide. The real history comes from the server's
// sampler (crates/tenko-api); its rules for the buckets are the unit tests' (history.test.ts).
//
// Scenarios:
// - A late client draws every tile from one history; a chart is one tab stop whose value text is
//   the readout, which the keyboard moves through; a burst of five seconds two hours back stands
//   above the scale in its ten-minute bucket; a controller that restarted says where its history
//   begins; axe finds nothing.
// - The charts glide at about 10 frames a second while the page is visible, and the frames stay
//   within M85's budget (p99 of a frame under 12 ms, the drawing under 10 % of one core), measured
//   over 60 s with all 25 tiles on screen; the main thread's busy share is attached beside it,
//   with what this test's stream costs while the charts stand still. A chart under the pointer
//   holds still while the others glide; nothing is drawn while the page is hidden or after "Pause
//   motion". Screenshots of the tiles in the light and the dark theme are attached.
// - Under reduced motion nothing glides: no animation frame is asked for, and a chart is drawn in
//   place once in ten seconds.
//
// The drawing is counted from outside: an init script counts the canvases' `clearRect` (one per
// drawing) and times the animation frame callbacks.
import { writeFile } from "node:fs/promises";
import type { Page } from "@playwright/test";
import { testHistory } from "../src/dashboard/historyTestData";
import { axeViolations } from "./support/axe";
import { expect, test } from "./support/fixtures";
import { dhcpPart, dnsPart, sample, type MetricsSnapshot } from "./support/metrics-mock";

const STREAM = /\/api\/v1\/events\?topics=metrics(&|$)/;
/** Tall enough for all 25 tiles at once: a chart off screen is not drawn. */
const VIEWPORT = { width: 1280, height: 4400 };

/** The snapshot of one controller with every role, at `at`. */
function snapshotAt(at: number): MetricsSnapshot {
  const own = sample(1, {
    at: new Date(at * 1000).toISOString(),
    dns: dnsPart({ recursion: { subqueries_per_second: 40, validation: { secure: 30, insecure: 5, bogus: 1, indeterminate: 0.5 } } }),
    dhcp: dhcpPart(),
    host: { cpu_percent: 12.5, memory_total: 8e9, memory_available: 5e9, disk_total: 128e9, disk_available: 64e9 },
  });
  return { nodes: [own], cluster: { ...own, node: null } };
}

/** Answers every connection of the tiles' stream with a fresh history and one snapshot at that moment. */
async function fakeHistoryStream(page: Page, options: { startedAgo?: number } = {}): Promise<void> {
  await page.goto("about:blank");
  await page.route(STREAM, async (route) => {
    const at = Date.now() / 1000;
    const history = testHistory({ at, startedAgo: options.startedAgo });
    const body = [
      { topic: "metrics", kind: "metrics.history", history },
      { topic: "metrics", kind: "metrics.snapshot", metrics: snapshotAt(at) },
    ]
      .map((data) => `event: metrics\ndata: ${JSON.stringify(data)}\n\n`)
      .join("");
    await route.fulfill({ status: 200, headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" }, body });
  });
}

/** Counts each canvas's drawings and times the animation frame callbacks, before the page's own script runs. */
async function instrument(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as unknown as { draws: number; frames: number[] };
    w.draws = 0;
    w.frames = [];
    const clear = CanvasRenderingContext2D.prototype.clearRect;
    CanvasRenderingContext2D.prototype.clearRect = function (this: CanvasRenderingContext2D, x: number, y: number, width: number, height: number) {
      w.draws += 1;
      const canvas = this.canvas as HTMLCanvasElement;
      canvas.dataset.draws = String(Number(canvas.dataset.draws ?? 0) + 1);
      clear.call(this, x, y, width, height);
    };
    const request = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = (callback) =>
      request((time) => {
        const start = performance.now();
        callback(time);
        w.frames.push(performance.now() - start);
      });
    // "Show all metrics" for the session (U3); about:blank has no storage.
    try {
      sessionStorage.setItem("tenko.dashboard.show-all", "1");
    } catch {
      // Nothing to switch.
    }
  });
}

const counts = (page: Page) => page.evaluate(() => ({ draws: (window as unknown as { draws: number }).draws, frames: (window as unknown as { frames: number[] }).frames.length }));
const chartDraws = (page: Page, name: string) => page.getByTestId(`metrics-history-${name}`).locator("canvas").evaluate((c) => Number((c as HTMLCanvasElement).dataset.draws ?? 0));

async function openTiles(page: Page): Promise<void> {
  await page.setViewportSize(VIEWPORT);
  await page.goto("/");
  await expect(page.getByTestId("metrics-tiles")).toHaveAttribute("data-controllers", "1");
  // Every tile's chart drew its history: some 200 buckets with data (a ratio's finest are 5 s).
  await expect(page.locator("[data-testid^='metrics-history-'][role='slider']")).toHaveCount(25);
  for (const chart of await page.locator("[data-testid^='metrics-history-'][role='slider']").all()) {
    await expect.poll(async () => Number(await chart.getAttribute("data-buckets")), { message: (await chart.getAttribute("data-testid")) ?? "" }).toBeGreaterThan(100);
  }
}

test("a late client draws every tile from one history, and each chart reads by keyboard", async ({ page, signedIn }) => {
  void signedIn;
  await fakeHistoryStream(page, { startedAgo: 30 * 3600 });
  await instrument(page);
  await openTiles(page);
  const chart = page.getByTestId("metrics-history-dns-queries");
  await expect(chart).toHaveAttribute("aria-label", /^DNS queries history\. Left and Right step one bucket/);
  // The text alternative names where the history begins.
  const alt = page.locator(`#${await chart.getAttribute("aria-describedby")}`);
  await expect(alt).toContainText(/^DNS queries: .* now\. Last minute: .* Last hour: mean .* No history before .*, when this controller started\.$/);
  // One tab stop; the focus reads the newest bucket, and the readout says the same.
  await chart.focus();
  await expect(chart).toHaveAttribute("aria-valuetext", /^DNS queries, .* · 1 sec · .*\/s\./);
  const readout = page.getByTestId("metrics-history-readout");
  await expect(readout).toBeVisible();
  expect(await chart.getAttribute("aria-valuetext")).toContain((await readout.locator(".value").textContent())!);
  // The burst two hours back stands above the scale in its ten-minute bucket.
  await page.keyboard.press("Home");
  let text = "";
  for (let i = 0; i < 300 && !text.includes("(above the scale)"); i++) {
    await page.keyboard.press("ArrowRight");
    text = (await chart.getAttribute("aria-valuetext")) ?? "";
  }
  expect(text).toMatch(/ · 10 min · 2 hours ago: [\d.,]+K?\/s mean\. Lowest [\d.,]+K?\/s, highest [\d.,]+K?\/s \(above the scale\)\./);
  await expect(readout).toContainText("(above the scale)");
  // Escape closes the readout and keeps the focus.
  await page.keyboard.press("Escape");
  await expect(readout).toHaveCount(0);
  await expect(chart).toBeFocused();
  expect(await axeViolations(page, "[data-testid='metrics-tiles']")).toEqual([]);
});

test("M85: the charts glide within the budget, hold under the pointer and stop while hidden or paused", async ({ page, signedIn }, testInfo) => {
  void signedIn;
  await fakeHistoryStream(page);
  await instrument(page);
  await openTiles(page);

  // A minute of gliding with all 25 charts on screen: the frames' times and the main thread's busy time.
  const session = await page.context().newCDPSession(page);
  await session.send("Performance.enable");
  const busy = async () => (await session.send("Performance.getMetrics")).metrics.find((m) => m.name === "TaskDuration")!.value;
  const start = await counts(page);
  const busyStart = await busy();
  const wallStart = Date.now();
  // test-lint: allow sleep the minute of gliding is the window M85 measures
  await page.waitForTimeout(60_000);
  const wall = (Date.now() - wallStart) / 1000;
  const busyShare = (await busy()) - busyStart;
  const frames = await page.evaluate((from) => (window as unknown as { frames: number[] }).frames.slice(from), start.frames);
  const sorted = [...frames].sort((a, b) => a - b);
  const p99 = sorted[Math.floor(sorted.length * 0.99)] ?? 0;
  const mean = frames.reduce((a, b) => a + b, 0) / Math.max(1, frames.length);
  const drawn = (await counts(page)).draws - start.draws;
  const result = {
    seconds: wall,
    charts: 25,
    framesDrawn: drawn / 25,
    framesPerSecond: drawn / 25 / wall,
    frameMeanMs: mean,
    frameP99Ms: p99,
    drawingShareOfOneCore: (frames.reduce((a, b) => a + b, 0) / 1000 / wall) * 100,
    mainThreadBusyShare: (busyShare / wall) * 100,
  };
  await writeFile(testInfo.outputPath("m85.json"), JSON.stringify(result, null, 2));
  await testInfo.attach("m85.json", { path: testInfo.outputPath("m85.json"), contentType: "application/json" });
  // About 10 frames a second (a busy runner drops some), each well inside the budget.
  expect(result.framesPerSecond).toBeGreaterThan(5);
  expect(result.framesPerSecond).toBeLessThan(12);
  expect(result.frameP99Ms).toBeLessThan(12);
  expect(result.drawingShareOfOneCore).toBeLessThan(10);

  for (const theme of ["light", "dark"]) {
    // Shift+T steps through the themes (system, light, dark); the charts read the colors again.
    await expect(async () => {
      if ((await page.evaluate(() => document.documentElement.dataset.theme)) !== theme) await page.keyboard.press("Shift+T");
      expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
    }).toPass();
    const drawn = await chartDraws(page, "requests");
    await expect.poll(() => chartDraws(page, "requests")).toBeGreaterThan(drawn + 2);
    const path = testInfo.outputPath(`metrics-history-${theme}.png`);
    await page.getByTestId("metrics-tiles").screenshot({ path });
    await testInfo.attach(`metrics-history-${theme}.png`, { path, contentType: "image/png" });
  }

  // Under the pointer the chart holds still and says so; the others go on.
  const held = page.getByTestId("metrics-history-dns-queries");
  await held.hover();
  await expect(held).toHaveClass(/is-held/);
  const heldBefore = await chartDraws(page, "dns-queries");
  const otherBefore = await chartDraws(page, "requests");
  await expect.poll(() => chartDraws(page, "requests")).toBeGreaterThan(otherBefore + 10);
  expect(await chartDraws(page, "dns-queries")).toBe(heldBefore);
  await page.mouse.move(0, 0);

  // A hidden page draws nothing and asks for no frame.
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  const hidden = await counts(page);
  // test-lint: allow sleep that nothing is drawn for a while is what this part checks
  await page.waitForTimeout(2500);
  // At most the frame that was already asked for.
  const whileHidden = await counts(page);
  expect(whileHidden.draws - hidden.draws).toBeLessThanOrEqual(25);
  expect(whileHidden.frames - hidden.frames).toBeLessThanOrEqual(1);
  await page.evaluate(() => {
    Reflect.deleteProperty(document, "hidden");
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(async () => (await counts(page)).draws).toBeGreaterThan(hidden.draws);

  // "Pause motion" stops every chart; the numbers go on.
  await page.getByTestId("metrics-pause-motion").click();
  await expect(page.getByTestId("metrics-pause-motion")).toHaveAttribute("aria-pressed", "true");
  const paused = await counts(page);
  // The main thread's busy share without the drawing: what this test's stream costs on its own.
  const pausedBusy = await busy();
  // test-lint: allow sleep that nothing is drawn for a while is what this part checks, and its busy time is measured
  await page.waitForTimeout(5000);
  const whilePaused = await counts(page);
  expect(whilePaused.draws - paused.draws).toBeLessThanOrEqual(25);
  expect(whilePaused.frames - paused.frames).toBeLessThanOrEqual(1);
  const baseline = { mainThreadBusyShareWhilePaused: (((await busy()) - pausedBusy) / 5) * 100 };
  await writeFile(testInfo.outputPath("m85-paused.json"), JSON.stringify(baseline, null, 2));
  await testInfo.attach("m85-paused.json", { path: testInfo.outputPath("m85-paused.json"), contentType: "application/json" });
  await page.getByTestId("metrics-pause-motion").click();
  await expect(page.getByTestId("metrics-pause-motion")).toHaveAttribute("aria-pressed", "false");
});

test("under reduced motion nothing glides: a chart is drawn in place once in ten seconds", async ({ page, signedIn }) => {
  void signedIn;
  await page.emulateMedia({ reducedMotion: "reduce" });
  await fakeHistoryStream(page);
  await instrument(page);
  await openTiles(page);
  const before = await chartDraws(page, "requests");
  // test-lint: allow sleep that a chart is redrawn once in ten seconds and not more is what this test checks
  await page.waitForTimeout(11_000);
  expect(await chartDraws(page, "requests")).toBeGreaterThanOrEqual(before + 1);
  expect(await chartDraws(page, "requests")).toBeLessThanOrEqual(before + 2);
  expect((await counts(page)).frames).toBe(0);
});
