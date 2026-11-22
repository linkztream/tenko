// Pages that borrow a text of another area's message pack show the text, not its key. Under the
// unit tests every message is in the core table, so only the built UI, with its lazily loaded
// packs, can show the difference. `expectRendered` (support/i18n.ts) looks for the keys of the
// English source in the visible text and in the aria-label, title and placeholder attributes.

import type { Page } from "@playwright/test";
import { expect, test } from "./support/fixtures";
import { messageKeys, expectRendered } from "./support/i18n";
import { withKey } from "./support/ui";

/** The document title is no key, once the page's own pack has arrived. */
async function expectTitleRendered(page: Page): Promise<void> {
  await expect.poll(async () => (await page.title()).split(/\s+/).filter((word) => messageKeys().has(word))).toEqual([]);
}

test("the security page and its prerelease dialog show no message keys", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/security");
  await expect(withKey(page, "toggle", "TGL-45")).toBeVisible();
  await expectRendered(page, page.locator("body"), "en");
  await expectTitleRendered(page);

  // The hint of the prerelease switch is a text of the updates pack.
  await withKey(page, "toggle", "TGL-45").getByTestId("toggle-edit").click();
  const dialog = page.getByTestId("dialog-toggle");
  await expect(dialog).toBeVisible();
  await expectRendered(page, dialog, "en");
});

test("the zone flip page shows no message keys", async ({ page, signedIn }) => {
  void signedIn;
  // The page is a stub that reads only the zone name from the address, so no zone is needed.
  await page.goto("/dns/zones/lab.example.test/flip");
  await expectRendered(page, page.getByTestId("page-migrate-zone-flip"), "en");
  await expectTitleRendered(page);
});
