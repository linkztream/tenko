// U3: the start page in five blocks (docs/plans/ui-plan.md section 5.1) against the real server.
//
// Scenarios:
// - The header names the node, its uptime as people say it, the free disk of its total, the store
//   and the version of the status; the blocks follow in reading order: the needs-attention strip,
//   the health row, the fullest prefixes beside the recent changes, the Hidden line.
// - The e2e server is one controller under the Lab profile without the `dns` and `dhcp` roles: no
//   service panel is drawn, the system panel has the controller's metrics (Lab's set), and the
//   Hidden line names DNS, DHCP and the jobs and connectors (Standard's); "Show all metrics" draws
//   every block and the tiles of every metric for the session, and "Show fewer metrics" takes
//   them away.
// - A network created through the API is a fullest prefix with its link, and the creation is a
//   person's change in the recent changes, with the label of the catalog and the code below it;
//   the System activity switch is a real checkbox.
// - Every block that is a link is a real link; axe finds nothing; Swedish.
//
// The findings of the strip come from the real index: discovery.spec.ts seeds proposals and
// checks the review line against the counts; the units of the page cover the rows to act on.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

/** Runs axe-core in the page (through the debugging protocol, since the CSP refuses injected tags). */
async function axeViolations(page: Page, selector: string): Promise<string[]> {
  await page.evaluate(await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8"));
  return page.evaluate(async (scope) => {
    const axe = (window as unknown as { axe: { run(context: string): Promise<{ violations: { id: string }[] }> } }).axe;
    return (await axe.run(scope)).violations.map((v) => v.id);
  }, selector);
}

/** The page's blocks that are drawn, in document order. */
async function blockOrder(page: Page): Promise<string[]> {
  const ids = ["dashboard-attention", "dashboard-health", "dashboard-dns", "dashboard-dhcp", "dashboard-system", "dashboard-utilization", "dashboard-audit", "hidden-line"];
  return page.getByTestId("page-dashboard").evaluate(
    (root, wanted) => [...root.querySelectorAll<HTMLElement>("[data-testid]")].map((e) => e.dataset.testid!).filter((id) => wanted.includes(id)),
    ids,
  );
}

test("the header says the node's facts and the blocks follow in reading order", async ({ page, api, signedIn }) => {
  void signedIn;
  const status = await api.get<Schemas["SystemStatus"]>("/system/status");
  await page.goto("/");
  const facts = page.getByTestId("dashboard-facts");
  await expect(facts).toContainText(/up (\d+ s|\d+ min|\d+ h \d+ min)/);
  await expect(facts).toContainText("store ");
  await expect(facts).toContainText(status.version);
  if (status.node.name) await expect(facts).toContainText(status.node.name);
  // The disk of the data directory is read on every platform.
  await expect(facts).toContainText(/\d+(\.\d)? of \d+(\.\d)? GiB free/);
  await expect(page.getByTestId("dashboard-attention")).toHaveAttribute("data-state", /attention|clear/);
  await expect(page.getByTestId("hidden-line")).toBeVisible();
  // Lab draws the controller's metrics in the system panel once the first sample is in.
  await expect(page.getByTestId("dashboard-system").getByTestId("dashboard-commit")).toBeVisible({ timeout: 5_000 });
  expect(await blockOrder(page)).toEqual(["dashboard-attention", "dashboard-health", "dashboard-system", "dashboard-utilization", "dashboard-audit", "hidden-line"]);
  // Every metric block of the health row is a real link.
  const blocks = page.getByTestId("dashboard-health").locator(".metric");
  const count = await blocks.count();
  expect(count).toBeGreaterThanOrEqual(4);
  for (let i = 0; i < count; i++) expect(await blocks.nth(i).evaluate((e) => e.tagName)).toBe("A");
});

test("one controller without DNS and DHCP under Lab: the Hidden line names what is not drawn, and Show all draws every metric", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/");
  const line = page.getByTestId("hidden-line");
  const items = line.getByTestId("hidden-line-item");
  // Lab draws the controller's metrics; the jobs and connectors are Standard's.
  await expect
    .poll(async () => items.evaluateAll((list) => list.map((e) => (e as HTMLElement).dataset.item)))
    .toEqual(expect.arrayContaining(["operations", "dns", "dhcp"]));
  await expect(line.locator("[data-item='controller']")).toHaveCount(0);
  await expect(line).toContainText("DNS (no node runs the dns role)");
  await expect(page.getByTestId("dashboard-dns")).toHaveCount(0);
  await expect(page.getByTestId("dashboard-dhcp")).toHaveCount(0);
  await expect(page.getByTestId("dashboard-health-jobs")).toHaveCount(0);

  const toggle = page.getByTestId("hidden-line-toggle");
  await expect(toggle).toHaveText("Show all metrics");
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("metrics-tiles")).toHaveAttribute("data-controllers", "1", { timeout: 5_000 });
  await expect(page.getByTestId("dashboard-health-jobs")).toBeVisible();
  await expect(page.getByTestId("dashboard-connectors")).toBeVisible();
  // The choice holds for the session.
  await page.reload();
  await expect(page.getByTestId("hidden-line-toggle")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("hidden-line-toggle").click();
  await expect(page.getByTestId("metrics-tiles")).toHaveCount(0);
});

test("a network created through the API is a fullest prefix, and its creation a person's change", async ({ page, api, signedIn }) => {
  void signedIn;
  await api.post("/prefixes", { cidr: "198.51.100.0/24", description: "Lab" });
  await page.goto("/");
  const panel = page.getByTestId("dashboard-utilization");
  const row = panel.locator('[data-testid="dashboard-prefix"][data-key="198.51.100.0/24"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText("Lab");
  await expect(row).toHaveAttribute("href", /\/ipam\/prefixes\/198\.51\.100\.0\/24/);

  const changes = page.getByTestId("dashboard-audit");
  const system = changes.getByTestId("dashboard-system-activity");
  await expect(system).toHaveAttribute("type", "checkbox");
  // People only: the creation is there with its label and its code below it.
  if (await system.isChecked()) await system.uncheck();
  const created = changes.getByTestId("dashboard-change").filter({ hasText: "ipam.prefix.create" });
  await expect(created.first()).toBeVisible();
  await expect(created.first().locator(".audit-action-label")).not.toBeEmpty();
  await expect(changes.locator('[data-testid="dashboard-change"][data-system="true"]')).toHaveCount(0);
  await system.check();
  await expect(system).toBeChecked();
});

test("the page passes axe", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/");
  await expect(page.getByTestId("dashboard-attention")).toHaveAttribute("data-state", /attention|clear/);
  await expect(page.getByTestId("dashboard-audit")).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-dashboard']")).toEqual([]);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the start page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/");
    await expect(page.getByTestId("dashboard-attention")).toHaveAttribute("data-state", /attention|clear/);
    await expect(page.getByTestId("hidden-line")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dashboard"), "sv", testInfo, "dashboard");
  });
});
