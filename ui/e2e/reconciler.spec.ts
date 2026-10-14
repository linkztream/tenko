// WP3.11d: the reconciler settings page (docs/reconciliation.md, section 3.1.1) against the real
// server.
//
// Scenarios:
// - The page shows the server's defaults: interval 300 s, adoption on, the seven settings in
//   human units.
// - A changed interval and orphan age are saved and shown again after a reload; the API agrees.
// - An interval of 10 s is refused inline and nothing is sent.
// - The keyboard reaches every field in order; axe finds nothing.
// - Swedish.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

type Settings = Schemas["ReconcilerSettings"];

test("shows the defaults of the server in human units", async ({ page, api, signedIn }) => {
  void signedIn;
  const stored = await api.get<Settings>("/settings/reconciler");
  expect(stored).toMatchObject({ interval_secs: 300, adopt: true });

  await page.goto("/settings/reconciler");
  await expect(page.getByTestId("page-reconciler")).toBeVisible();
  await expect(page.getByTestId("field-interval")).toHaveValue("300");
  await expect(page.getByTestId("field-debounce")).toHaveValue("2");
  await expect(page.getByTestId("field-refresh")).toHaveValue("15");
  await expect(page.getByTestId("field-purge")).toHaveValue("1");
  await expect(page.getByTestId("field-orphan")).toHaveValue("7");
  await expect(page.getByTestId("field-retention")).toHaveValue("30");
  await expect(page.getByTestId("field-adopt")).toBeChecked();
});

test("saves a changed interval and orphan age and shows them after a reload", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/reconciler");
  await page.getByTestId("field-interval").fill("120");
  await page.getByTestId("field-orphan").fill("14");
  await page.getByTestId("form-submit").click();

  await expect.poll(async () => (await api.get<Settings>("/settings/reconciler")).interval_secs).toBe(120);
  const stored = await api.get<Settings>("/settings/reconciler");
  expect(stored).toMatchObject({ interval_secs: 120, orphan_after_secs: 14 * 86_400, adopt: true, refresh_secs: 900 });

  await page.reload();
  await expect(page.getByTestId("field-interval")).toHaveValue("120");
  await expect(page.getByTestId("field-orphan")).toHaveValue("14");
});

test("refuses an interval of 10 seconds inline and sends nothing", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/reconciler");
  const writes: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "PUT") writes.push(request.url());
  });
  await page.getByTestId("field-interval").fill("10");
  await page.getByTestId("form-submit").click();
  await expect(page.getByTestId("field-interval")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("field-error")).toHaveAttribute("data-field", "interval");
  expect(writes).toEqual([]);
  expect((await api.get<Settings>("/settings/reconciler")).interval_secs).toBe(300);
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

test("the keyboard reaches every field and axe finds nothing", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/reconciler");
  await expect(page.getByTestId("reconciler-form")).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-reconciler']")).toEqual([]);
  await page.getByTestId("field-adopt").focus();
  const order = ["field-adopt", "field-interval", "field-debounce", "field-refresh", "field-purge", "field-orphan", "field-retention", "form-submit"];
  for (const [index, id] of order.entries()) {
    if (index > 0) await page.keyboard.press("Tab");
    await expect(page.getByTestId(id)).toBeFocused();
  }
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the reconciler page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/reconciler");
    await expect(page.getByTestId("reconciler-form")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-reconciler"), "sv", testInfo, "reconciler");
  });
});
