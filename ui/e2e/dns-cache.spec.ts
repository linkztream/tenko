// The cache tab of the DNS page (/dns/cache), next to the query log: what a node's cache holds,
// read when asked as a tree of names, narrowed to a suffix and flushed, with expanding and
// selecting folders never reading; the tree beside the table on a wide viewport and above it on a
// narrow one; the node shared with the query log's tab.
//
// THE NODE'S DNS STATUS AND CACHE ROUTES ARE FAKED (support/dns-resolver-mock.ts and
// support/dns-cache-mock.ts, which say why): the e2e server is one controller without the `dns`
// role. The real listing and its audit are proven in Rust (see the cache mock).

import type { Page } from "@playwright/test";
import { FakeCache } from "./support/dns-cache-mock";
import { FakeResolver } from "./support/dns-resolver-mock";
import { expect, test } from "./support/fixtures";

/** Opens the DNS page and goes to the cache through its tab, as a person does. */
async function openCache(page: Page): Promise<void> {
  await page.goto("/dns");
  await page.getByTestId("dns-nav").locator('[data-key="cache"]').click();
  await expect(page.getByTestId("page-dns-cache")).toBeVisible();
}

// What the cache holds, read when asked as a tree of names, narrowed to a suffix
// and flushed; expanding and selecting folders never reads.
test("lists what the cache holds and flushes a suffix", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  const cache = await FakeCache.install(page);
  await openCache(page);
  const section = page.getByTestId("dns-cache");
  await expect(section).toBeVisible();
  // The explanation sits behind the info button beside the title (U2), and Esc puts it away.
  await expect(page.getByTestId("dns-cache-audit-note")).toHaveCount(0);
  await page.getByTestId("page-info").click();
  await expect(page.getByTestId("page-info")).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByTestId("dns-cache-audit-note")).toContainText("audit log");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("dns-cache-audit-note")).toHaveCount(0);
  await expect(page.getByTestId("page-info")).toBeFocused();
  expect(cache.requests).toEqual([]);

  await section.getByTestId("dns-cache-show").click();
  const folders = section.getByTestId("dns-cache-node");
  await expect(folders).toHaveCount(4);
  await expect(folders.first()).toHaveText("(root)");
  await expect(folders.first()).toHaveAttribute("aria-selected", "true");
  await expect(section.getByTestId("dns-cache-folder-row")).toHaveCount(3);

  // Open test and example.test from the right pane, as in the Windows DNS manager.
  await section.locator('[data-testid="dns-cache-folder-row"][data-key="test"]').dblclick();
  await section.locator('[data-testid="dns-cache-folder-row"][data-key="example.test"]').press("Enter");
  await expect(section.locator('[data-testid="dns-cache-node"][aria-selected="true"]')).toHaveAttribute("data-key", "example.test");
  const rows = section.getByTestId("dns-cache-row");
  await expect(rows).toHaveCount(7);
  await expect(rows.first()).toContainText("(same as parent folder)");
  await expect(section.locator('[data-testid="dns-cache-row"][data-stale="true"]')).toHaveAttribute("data-key", "missing.example.test");
  await expect(section.locator('[data-testid="dns-cache-row"][data-covered="A"]').getByTestId("dns-cache-data")).toHaveText(
    "A, signer example.test, expires 2026-11-12 02:08",
  );
  await section.getByTestId("dns-cache-tree").press("Home");
  await expect(folders.first()).toHaveAttribute("aria-selected", "true");
  expect(cache.requests).toHaveLength(1);

  await section.getByTestId("field-cache-suffix").fill("www.example.test");
  await section.getByTestId("field-cache-suffix").press("Enter");
  await expect(rows).toHaveCount(4);
  await expect(section.locator('[data-testid="dns-cache-node"][aria-selected="true"]')).toHaveAttribute("data-key", "www.example.test");
  await expect(rows.first().getByTestId("dns-cache-data")).toHaveText("CNAME cdn.example.test, 192.0.2.80");

  await section.getByTestId("dns-cache-flush").click();
  const dialog = page.getByTestId("dns-cache-flush-dialog");
  await expect(dialog).toContainText("Flush www.example.test from the cache?");
  await dialog.getByTestId("confirm-ok").click();
  await expect(dialog).toHaveCount(0);
  await expect(section.getByTestId("dns-cache-empty")).toBeVisible();
  expect(cache.requests.filter((r) => r.method === "POST")).toEqual([
    { method: "POST", path: "/api/v1/nodes/1/dns/cache/flush", query: { suffix: "www.example.test" } },
  ]);
  expect(cache.requests.filter((r) => r.method === "GET").map((r) => r.query.suffix ?? "")).toEqual(["", "www.example.test", "www.example.test"]);
  expect(cache.requests.filter((r) => r.method === "GET").every((r) => r.query.limit === "1000")).toBe(true);
  expect(cache.state.entries).toHaveLength(5);
});

// cache-browse: the tree beside the table on a wide viewport, above it at 360 px, with no
// horizontal scroll of the page.
test("lays the cache tree out beside the table and above it on a narrow viewport", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  await FakeCache.install(page);
  await openCache(page);
  const section = page.getByTestId("dns-cache");
  await section.getByTestId("field-cache-suffix").fill("example.test");
  await section.getByTestId("dns-cache-show").click();
  await expect(section.getByTestId("dns-cache-row")).toHaveCount(7);
  const boxes = async () => {
    const tree = await section.getByTestId("dns-cache-tree").boundingBox();
    const table = await section.getByTestId("dns-cache-table").boundingBox();
    if (!tree || !table) throw new Error("no layout");
    return { tree, table };
  };
  await page.setViewportSize({ width: 1600, height: 900 });
  const wide = await boxes();
  expect(wide.table.x).toBeGreaterThanOrEqual(wide.tree.x + wide.tree.width);
  await page.setViewportSize({ width: 360, height: 800 });
  await expect(async () => {
    const narrow = await boxes();
    expect(narrow.table.y).toBeGreaterThanOrEqual(narrow.tree.y + narrow.tree.height);
  }).toPass();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
});

test("keeps the node when switching between the query log and the cache", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  const cache = await FakeCache.install(page);
  await page.goto("/dns/log");
  await expect(page.getByTestId("page-dns-log")).toBeVisible();
  const node = page.getByTestId("field-node");
  await expect(node).toHaveValue("1");

  const nav = page.getByTestId("dns-nav");
  await nav.locator('[data-key="cache"]').click();
  await expect(page).toHaveURL(/\/dns\/cache$/);
  await expect(page.getByTestId("page-dns-cache")).toBeVisible();
  await expect(nav.locator('[data-key="cache"]')).toHaveAttribute("aria-current", "page");
  await expect(nav.locator("a").last()).toHaveAttribute("data-key", "cache");
  await expect(node).toHaveValue("1");
  // Switching reads nothing from the cache: only the press of the button does.
  expect(cache.requests).toEqual([]);

  await page.getByTestId("dns-cache-show").click();
  await expect(page.getByTestId("dns-cache-node").first()).toBeVisible();
  expect(cache.requests.map((r) => r.path)).toEqual(["/api/v1/nodes/1/dns/cache"]);

  await nav.locator('[data-key="log"]').click();
  await expect(page.getByTestId("page-dns-log")).toBeVisible();
  await expect(node).toHaveValue("1");
});

// One long value must not take over the page: the data cell is clamped to three lines until its
// button opens it, and the table stays inside a 360 px viewport.
test("clamps a long value in the data column until its button is pressed", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  const cache = await FakeCache.install(page);
  cache.state.entries.push({
    name: "long.example.test",
    type: "TXT",
    rcode: 0,
    ttl: 300,
    stale: false,
    hits: 1,
    state: "unvalidated",
    records: [{ type: "TXT", strings: ["v=long ".padEnd(4000, "0123456789abcdef")] }],
  });
  await openCache(page);
  const section = page.getByTestId("dns-cache");
  await section.getByTestId("field-cache-suffix").fill("long.example.test");
  await section.getByTestId("dns-cache-show").click();
  const row = section.locator('[data-testid="dns-cache-row"][data-type="TXT"]');
  await expect(row).toHaveCount(1);
  const toggle = row.getByTestId("dns-cache-data-toggle");
  await expect(toggle).toHaveText("Show all");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect((await row.boundingBox())?.height ?? Infinity).toBeLessThan(200);

  await page.setViewportSize({ width: 360, height: 800 });
  expect((await row.boundingBox())?.height ?? Infinity).toBeLessThan(200);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);

  await toggle.click();
  await expect(toggle).toHaveText("Show less");
  expect((await row.boundingBox())?.height ?? 0).toBeGreaterThan(200);
  await toggle.click();
  await expect(toggle).toHaveText("Show all");
  expect((await row.boundingBox())?.height ?? Infinity).toBeLessThan(200);
});
