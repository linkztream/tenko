// The layout of the live metrics on the start page: every tile as tall as the others whatever it
// holds, the rows of each group full (the controller's eight tiles four to a row, the DNS six
// three to a row), no tile overlapping another and no gap in a row, and nothing cut off inside
// a tile; at 1280 and 1920 pixels wide.
//
// The e2e server does not run the `dns` role, so this scenario FAKES THE METRICS STREAM: the
// request for the `metrics` topic is answered with half a minute of the dev mock's samples of a
// controller with the role (`mockHistory` of support/metrics-mock.ts), so every DNS tile has its
// chart and its lists. What it proves is the shape of the tiles and the grid; the figures come
// from the server's registry and are covered by metrics.spec.ts and the Rust tests.

import type { Page, TestInfo } from "@playwright/test";
import { expect, test } from "./support/fixtures";
import { fakeMetricsStream, mockHistory } from "./support/metrics-mock";

const CONTROLLER = ["requests", "commit", "store", "raft", "jobs", "ingest", "sse", "nodes"];
const DNS = ["dns-queries", "dns-cache", "dns-answers", "dns-blocked", "dns-upstreams", "dns-encrypted"];
// WP8.7: the six DHCP tiles, three to a row like the DNS group.
const DHCP = ["dhcp-leases", "dhcp-ack", "dhcp-active", "dhcp-pools", "dhcp-naks", "dhcp-ddns"];

interface Box {
  name: string;
  x: number;
  y: number;
  width: number;
  height: number;
  /** The lowest bottom edge of the tile's content, and of the lists inside its chart area. */
  contentBottom: number;
  chartBottom: number;
  listBottom: number | null;
}

async function tileBoxes(page: Page): Promise<{ tiles: Box[]; grid: { x: number; width: number } }> {
  return page.getByTestId("metrics-tiles").evaluate((root) => {
    const grid = root.querySelector(".metrics-grid")!.getBoundingClientRect();
    const tiles = [...root.querySelectorAll<HTMLElement>("[data-testid^='metrics-tile-']")].map((tile) => {
      const box = tile.getBoundingClientRect();
      const chart = tile.querySelector(".metrics-chart")!.getBoundingClientRect();
      const rows = [...tile.querySelectorAll(".metrics-chart li")].map((li) => li.getBoundingClientRect().bottom);
      const padding = parseFloat(getComputedStyle(tile).paddingBlockEnd);
      return {
        name: tile.dataset.testid!.replace("metrics-tile-", ""),
        x: box.x,
        y: box.y + window.scrollY,
        width: box.width,
        height: box.height,
        contentBottom: tile.querySelector(".metrics-foot")!.getBoundingClientRect().bottom - (box.bottom - padding),
        chartBottom: chart.bottom,
        listBottom: rows.length > 0 ? Math.max(...rows) : null,
      };
    });
    return { tiles, grid: { x: grid.x, width: grid.width } };
  });
}

/** The tiles of a group in rows, top to bottom. */
function rows(tiles: Box[]): Box[][] {
  const out: Box[][] = [];
  for (const tile of [...tiles].sort((a, b) => a.y - b.y || a.x - b.x)) {
    const row = out.at(-1);
    if (row && Math.abs(row[0]!.y - tile.y) < 1) row.push(tile);
    else out.push([tile]);
  }
  return out;
}

function overlaps(a: Box, b: Box): boolean {
  return a.x < b.x + b.width - 0.5 && b.x < a.x + a.width - 0.5 && a.y < b.y + b.height - 0.5 && b.y < a.y + a.height - 0.5;
}

async function checkLayout(page: Page, testInfo: TestInfo, width: number): Promise<void> {
  // Tall enough for every tile, so the screenshot shows them all.
  await page.setViewportSize({ width, height: 1600 });
  // WP8.7: a controller with the `dhcp` role too, so the DHCP group is checked as well.
  await fakeMetricsStream(page, mockHistory(30, true, true));
  await page.goto("/");
  const root = page.getByTestId("metrics-tiles");
  await expect(root).toHaveAttribute("data-controllers", "1");
  await expect(page.getByTestId("metrics-tile-dns-queries")).toHaveAttribute("data-value", /.+/);
  await expect(page.getByTestId("metrics-tile-dns-answers").getByTestId("metrics-dns-rcode")).toHaveCount(5);

  const { tiles, grid } = await tileBoxes(page);
  await expect(page.getByTestId("metrics-tile-dhcp-pools").getByTestId("metrics-dhcp-pool")).toHaveCount(3);
  expect(tiles.map((t) => t.name)).toEqual([...CONTROLLER, ...DNS, ...DHCP]);

  // One height for every tile, and nothing in a tile cut off at its bottom or out of its chart area.
  const height = tiles[0]!.height;
  for (const tile of tiles) {
    expect(Math.abs(tile.height - height), `${tile.name} is ${tile.height}px, not ${height}px`).toBeLessThan(0.5);
    expect(tile.contentBottom, `${tile.name}: the footer runs past the padding`).toBeLessThanOrEqual(0.5);
    if (tile.listBottom !== null) expect(tile.listBottom, `${tile.name}: the list runs out of the chart area`).toBeLessThanOrEqual(tile.chartBottom + 0.5);
  }

  // No tile overlaps another.
  for (const [i, a] of tiles.entries()) for (const b of tiles.slice(i + 1)) expect(overlaps(a, b), `${a.name} overlaps ${b.name}`).toBe(false);

  // Each group fills its rows: the same number of tiles in every row, equally wide, from the left
  // edge of the grid to its right edge with one gap between neighbours, and one gap between rows.
  const gap = await page.locator(".metrics-grid").evaluate((el) => parseFloat(getComputedStyle(el).columnGap));
  const groups = [
    { names: CONTROLLER, columns: 4 },
    { names: DNS, columns: 3 },
    { names: DHCP, columns: 3 },
  ];
  for (const group of groups) {
    const lines = rows(tiles.filter((t) => group.names.includes(t.name)));
    expect(lines.map((line) => line.length)).toEqual(lines.map(() => group.columns));
    const tileWidth = (grid.width - (group.columns - 1) * gap) / group.columns;
    for (const line of lines) {
      line.sort((a, b) => a.x - b.x);
      expect(Math.abs(line[0]!.x - grid.x)).toBeLessThan(1);
      const last = line.at(-1)!;
      expect(Math.abs(last.x + last.width - (grid.x + grid.width))).toBeLessThan(1);
      for (const [i, tile] of line.entries()) {
        expect(Math.abs(tile.width - tileWidth), `${tile.name} width`).toBeLessThan(1);
        if (i > 0) expect(Math.abs(tile.x - (line[i - 1]!.x + line[i - 1]!.width) - gap), `gap before ${tile.name}`).toBeLessThan(1);
      }
    }
    for (const [i, line] of lines.entries()) {
      if (i > 0) expect(Math.abs(line[0]!.y - (lines[i - 1]![0]!.y + height) - gap), `gap above row ${i + 1}`).toBeLessThan(1);
    }
  }

  await testInfo.attach(`metrics-${width}`, { body: await root.screenshot(), contentType: "image/png" });
}

test("every metrics tile is as tall as the others and the rows are full at 1280 px (faked stream)", async ({ page, signedIn }, testInfo) => {
  void signedIn;
  await checkLayout(page, testInfo, 1280);
});

test("every metrics tile is as tall as the others and the rows are full at 1920 px (faked stream)", async ({ page, signedIn }, testInfo) => {
  void signedIn;
  await checkLayout(page, testInfo, 1920);
});
