// WP5.5: the block lists of the DNS area. Create a list from a URL, fetch it now (a job the page
// follows and links to) and see its compiled version; upload the file of an uploaded list
// (`PUT /dns/lists/{id}/file`); Swedish; and what the page shows against the real server, which
// answers the list routes with 501 until WP5.2 is merged.
//
// THE FIRST SCENARIOS FAKE THE RESOLVER ROUTES (support/dns-resolver-mock.ts, which says why);
// the last one runs against the real server.

import type { Locator, Page } from "@playwright/test";
import { LIST_URLS } from "../src/api/mock/dns-resolver-model";
import { FakeResolver, withDns } from "./support/dns-resolver-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

const list = (page: Page, name: string): Locator => gridRow(page, "dns-lists", name);

async function rowAction(page: Page, row: Locator, action: string): Promise<void> {
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator(`[data-key="${action}"]`).click();
}

test("creates a list from a URL, fetches it now and shows the version", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeResolver.install(page);
  await page.goto("/dns/lists");
  await expect(page.getByTestId("page-dns-lists")).toBeVisible();
  await expect(list(page, "Ads").getByTestId("list-version")).toHaveAttribute("data-count", "4");
  await expect(list(page, "Local").getByTestId("list-disabled")).toBeVisible();

  await page.getByTestId("dns-list-create").click();
  const form = page.getByTestId("dialog-list-form");
  await form.getByTestId("field-name").fill("Trackers");
  await form.getByTestId("field-source-url").check();
  await form.getByTestId("field-url").fill(LIST_URLS.trackers);
  await form.getByTestId("field-interval").fill("12");
  await form.getByTestId("field-format").selectOption("domains");
  await form.getByTestId("field-action").selectOption("nodata");
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
  const trackers = list(page, "Trackers");
  await expect(trackers.getByTestId("list-source")).toHaveAttribute("data-kind", "url");
  await expect(trackers.getByTestId("list-action")).toHaveAttribute("data-kind", "nodata");
  await expect(trackers.getByTestId("list-version")).toHaveCount(0);
  expect(fake.sent.find((s) => s.method === "POST")?.body).toMatchObject({
    name: "Trackers",
    source: { kind: "url", url: LIST_URLS.trackers },
    interval_hours: 12,
    action: { kind: "nodata" },
  });

  // Fetch now: the job runs, the page follows it and reads the list again.
  await rowAction(page, trackers, "fetch");
  const job = page.getByTestId("list-job");
  await expect(job).toHaveAttribute("data-state", "succeeded");
  await expect(job.getByTestId("list-job-open")).toHaveAttribute("href", /^\/jobs\/[0-9a-f-]{36}$/);
  await expect(trackers.getByTestId("list-version")).toHaveAttribute("data-count", "2");
  expect(fake.sent.at(-1)?.path).toMatch(/\/dns\/lists\/[0-9a-f-]{36}\/fetch$/);
});

test("uploads the file of an uploaded list", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeResolver.install(page);
  await page.goto("/dns/lists");
  const local = list(page, "Local");
  await expect(local).toBeVisible();
  await rowAction(page, local, "upload");
  const dialog = page.getByTestId("dialog-list-upload");
  await dialog.getByTestId("field-file").setInputFiles({
    name: "local.hosts",
    mimeType: "text/plain",
    buffer: Buffer.from("# blocked at home\n0.0.0.0 ads.example.test\n0.0.0.0 tracker.example.test pixel.example.test\n"),
  });
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByTestId("list-job")).toHaveAttribute("data-state", "succeeded");
  await expect(local.getByTestId("list-version")).toHaveAttribute("data-count", "3");
  const put = fake.sent.find((s) => s.method === "PUT");
  expect(put?.path).toMatch(/\/dns\/lists\/[0-9a-f-]{36}\/file$/);
  expect(String(put?.body)).toContain("tracker.example.test");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the block lists page and its form in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeResolver.install(page);
    await page.goto("/dns/lists");
    await expect(list(page, "Ads")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dns-lists"), "sv", testInfo, "dns-lists");
    await page.getByTestId("dns-list-create").click();
    await expectRendered(page, page.getByTestId("dialog-list-form"), "sv", testInfo, "dns-list-form");
  });
});

test("says so against the real server, which answers the list routes with 501 until WP5.2 is merged", async ({ page, signedIn }) => {
  void signedIn;
  // No fake of the list routes. The module list names DNS so that the area is shown. The
  // annotation `dns-lists` notes which answer came: 501, the module off, or the real lists.
  await page.route(/\/api\/v1\/system\/modules(\?|$)/, (route) => withDns(route));
  await page.goto("/dns/lists");
  await expect(page.getByTestId("page-dns-lists")).toBeVisible();
  const notBuilt = page.getByTestId("dns-not-built");
  const off = page.getByTestId("dns-off");
  const grid = page.getByTestId("grid-dns-lists");
  await expect(notBuilt.or(off).or(grid)).toBeVisible();
  const answer = (await notBuilt.isVisible()) ? "501" : (await off.isVisible()) ? "module_off" : "served";
  test.info().annotations.push({ type: "dns-lists", description: answer });
  if (answer !== "served") await expect(page.getByTestId("dns-list-create")).toHaveCount(0);
});
