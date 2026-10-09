// Scenario 7: the UI language (API-08, API-21). The UI follows the browser's language when
// the user has chosen none, and the per-user choice in the account menu wins over the
// browser and survives a reload. The document language (`<html lang>`) tells which table
// is in use, so no translated text is asserted. A screenshot of the dashboard in each
// language is kept under e2e/.artifacts/ for the report.

import { resolve } from "node:path";
import type { Page, TestInfo } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { openAccountMenu } from "./support/ui";

const ARTIFACTS = resolve(import.meta.dirname, ".artifacts");

async function documentLanguage(page: Page): Promise<string> {
  return page.evaluate(() => document.documentElement.lang);
}

async function expectLanguage(page: Page, language: string): Promise<void> {
  await expect.poll(() => documentLanguage(page)).toBe(language);
}

/** A screenshot of the dashboard once its data has loaded, kept and attached. */
async function dashboardShot(page: Page, testInfo: TestInfo, language: string): Promise<void> {
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  await expect(page.getByTestId("dashboard-utilization")).toBeVisible();
  await expect(page.getByTestId("dashboard-audit")).toBeVisible();
  const path = resolve(ARTIFACTS, `dashboard-${language}.png`);
  await page.screenshot({ path, fullPage: true });
  await testInfo.attach(`dashboard-${language}`, { path, contentType: "image/png" });
}

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows Swedish until the user picks English, which wins over the browser", async ({ page, api, signedIn }, testInfo) => {
    // Something on the dashboard: two networks and an address.
    for (const cidr of ["192.0.2.0/24", "198.51.100.0/24"]) await api.post("/prefixes", { cidr });
    await api.post("/addresses", { ip: "192.0.2.10", dns_name: "nas.example.test" });
    expect(signedIn.session.user.language ?? null).toBeNull();

    await page.reload();
    await expectLanguage(page, "sv");
    await dashboardShot(page, testInfo, "sv");

    // The per-user choice in the account menu.
    const menu = await openAccountMenu(page);
    await menu.getByTestId("field-language").selectOption("en");
    await expectLanguage(page, "en");
    const user = await api.get<Schemas["UserInfo"]>(`/users/${signedIn.session.user.id}`);
    expect(user.language).toBe("en");
    await page.keyboard.press("Escape");

    // It is stored with the user, so it outlasts a reload in a Swedish browser.
    await page.reload();
    await expectLanguage(page, "en");
    await dashboardShot(page, testInfo, "en");

    // Back to automatic: the browser's language again.
    const again = await openAccountMenu(page);
    await again.getByTestId("field-language").selectOption("");
    await expectLanguage(page, "sv");
    expect((await api.session()).user.language ?? null).toBeNull();
  });
});

test.describe("an English browser", () => {
  test.use({ locale: "en-US" });

  test("switches to Swedish for a user who picks it, also on the sign-in page", async ({ page, api, signedIn }) => {
    await expectLanguage(page, "en");
    const menu = await openAccountMenu(page);
    await menu.getByTestId("field-language").selectOption("sv");
    await expectLanguage(page, "sv");
    await page.reload();
    await expectLanguage(page, "sv");
    expect((await api.session()).user.id).toBe(signedIn.session.user.id);

    // Before sign-in the browser decides; a choice on the sign-in page is kept locally.
    await api.logout();
    await page.goto("/signin");
    await expect(page.getByTestId("page-signin")).toBeVisible();
    await expectLanguage(page, "en");
    await page.getByTestId("field-language").selectOption("sv");
    await expectLanguage(page, "sv");
    await page.reload();
    await expectLanguage(page, "sv");
  });
});
