// WP3.11d: the guardrails page (docs/connectors-unifi.md, section 6) against the real server.
//
// Scenarios:
// - The page shows the default: ten parallel writes and no protected paths.
// - A VLAN path and a client path are added and saved; both are shown after a reload and the API
//   agrees.
// - Removing one path and saving leaves the other alone.
// - max_parallel 0 is refused inline and nothing is sent.
// - The add dialog works with the keyboard and keeps focus inside; axe finds nothing on the page
//   and in the dialog.
// - Swedish.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

type Guardrails = Schemas["Guardrails"];

async function addVlan(page: Page, vid: string): Promise<void> {
  await page.getByTestId("guardrails-add").click();
  const dialog = page.getByTestId("dialog-guardrail-path");
  await dialog.getByTestId("field-kind").selectOption("vlan");
  await dialog.getByTestId("field-vid").fill(vid);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();
}

async function addClient(page: Page, mac: string): Promise<void> {
  await page.getByTestId("guardrails-add").click();
  const dialog = page.getByTestId("dialog-guardrail-path");
  await dialog.getByTestId("field-kind").selectOption("client");
  await dialog.getByTestId("field-mac").fill(mac);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();
}

test("shows the default of ten parallel writes and no paths", async ({ page, api, signedIn }) => {
  void signedIn;
  expect(await api.get<Guardrails>("/settings/guardrails")).toEqual({ max_parallel: 10, protected: [] });
  await page.goto("/settings/guardrails");
  await expect(page.getByTestId("page-guardrails")).toBeVisible();
  await expect(page.getByTestId("field-max_parallel")).toHaveValue("10");
  await expect(page.getByTestId("guardrails-empty")).toBeVisible();
  await expect(page.getByTestId("guardrails-note")).toBeVisible();
});

test("adds a VLAN path and a client path and shows both after a reload", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/guardrails");
  await addVlan(page, "30");
  await addClient(page, "00-00-5E-00-53-01");
  await expect(page.getByTestId("guardrail-path")).toHaveCount(2);
  // Nothing is stored before Save.
  expect((await api.get<Guardrails>("/settings/guardrails")).protected).toEqual([]);
  await page.getByTestId("form-submit").click();

  await expect.poll(async () => (await api.get<Guardrails>("/settings/guardrails")).protected.length).toBe(2);
  expect((await api.get<Guardrails>("/settings/guardrails")).protected).toEqual([
    { type: "vlan", vid: 30 },
    { type: "client", mac: "00:00:5e:00:53:01" },
  ]);

  await page.reload();
  const rows = page.getByTestId("guardrail-path");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toHaveAttribute("data-key", "vlan:30");
  await expect(rows.nth(1)).toHaveAttribute("data-key", "client:00:00:5e:00:53:01");
});

test("removing one path and saving leaves the other alone", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/guardrails");
  await addVlan(page, "30");
  await addClient(page, "00:00:5e:00:53:02");
  await page.getByTestId("form-submit").click();
  await expect.poll(async () => (await api.get<Guardrails>("/settings/guardrails")).protected.length).toBe(2);

  await page.reload();
  const first = page.getByTestId("guardrail-path").first();
  await expect(first).toHaveAttribute("data-key", "vlan:30");
  await first.getByTestId("guardrail-remove").click();
  await expect(page.getByTestId("guardrail-path")).toHaveCount(1);
  await page.getByTestId("form-submit").click();
  await expect
    .poll(async () => (await api.get<Guardrails>("/settings/guardrails")).protected)
    .toEqual([{ type: "client", mac: "00:00:5e:00:53:02" }]);
});

test("refuses max_parallel 0 inline and sends nothing", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/guardrails");
  const writes: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "PUT") writes.push(request.url());
  });
  await page.getByTestId("field-max_parallel").fill("0");
  await expect(page.getByTestId("field-max_parallel")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("field-error")).toHaveAttribute("data-field", "max_parallel");
  await page.getByTestId("form-submit").click();
  expect(writes).toEqual([]);
  expect((await api.get<Guardrails>("/settings/guardrails")).max_parallel).toBe(10);
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

test("the add dialog works with the keyboard, keeps focus inside and passes axe", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/guardrails");
  await expect(page.getByTestId("guardrails-form")).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-guardrails']")).toEqual([]);
  await page.getByTestId("guardrails-add").focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByTestId("dialog-guardrail-path");
  await expect(dialog).toBeVisible();
  expect(await axeViolations(page, "[data-testid='dialog-guardrail-path']")).toEqual([]);
  for (let i = 0; i < 10; i += 1) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest("[data-testid='dialog-guardrail-path']"))).toBe(true);
  }
  // Enter in a field adds the path; Escape closes the dialog and returns the focus.
  await dialog.getByTestId("field-kind").focus();
  await page.keyboard.press("Tab");
  await page.keyboard.type("30");
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("guardrail-path")).toHaveCount(1);
  await page.getByTestId("guardrails-add").click();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("guardrails-add")).toBeFocused();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the guardrails page and its dialog in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/guardrails");
    await expect(page.getByTestId("guardrails-form")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-guardrails"), "sv", testInfo, "guardrails");
    await page.getByTestId("guardrails-add").click();
    await expectRendered(page, page.getByTestId("dialog-guardrail-path"), "sv", testInfo, "guardrails-dialog");
  });
});
