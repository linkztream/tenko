// WP4.5: the TSIG keys of the DNS area (scope `dns.keys`, administrators). Generate a key and
// see its secret this once (the dialog stays until the person confirms it is stored), import a
// key with a secret the person has, refuse a name that exists, delete a key; the key pages are
// not offered to a viewer; Swedish.
//
// THESE SCENARIOS FAKE THE DNS ROUTES (support/dns-mock.ts, which says why); the rest of the
// API is the real server.

import { signInAsViewer } from "./support/accounts";
import { FakeDns } from "./support/dns-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

test("generates a key and shows its secret only once", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto("/dns/keys");
  await expect(gridRow(page, "dns-keys", "xfr.example.test")).toBeVisible();

  await page.getByTestId("dns-key-create").click();
  const form = page.getByTestId("dialog-key-form");
  await form.getByTestId("field-name").fill("ddns.example.test");
  await form.getByTestId("field-algorithm").selectOption("hmac-sha512");
  await form.getByTestId("form-submit").click();

  const shown = page.getByTestId("dialog-key-created");
  const secret = (await shown.getByTestId("key-secret").innerText()).trim();
  expect(secret).toMatch(/^[A-Za-z0-9+/]{40,}={0,2}$/);
  // The dialog stays until the secret is stored: Close is disabled and Esc does nothing.
  await expect(shown.getByTestId("key-done")).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(shown).toBeVisible();
  await shown.getByTestId("key-stored").check();
  await shown.getByTestId("key-done").click();
  await expect(shown).toHaveCount(0);

  await expect(gridRow(page, "dns-keys", "ddns.example.test")).toBeVisible();
  await expect(gridRow(page, "dns-keys", "ddns.example.test").locator('[data-col="algorithm"]')).toHaveText("hmac-sha512");
  // Never again: neither the list nor a reload shows the secret.
  await expect(page.getByText(secret)).toHaveCount(0);
  await page.reload();
  await expect(gridRow(page, "dns-keys", "ddns.example.test")).toBeVisible();
  await expect(page.getByText(secret)).toHaveCount(0);
  expect(fake.sent.filter((s) => s.method === "POST").map((s) => s.body)).toEqual([
    { name: "ddns.example.test", algorithm: "hmac-sha512", description: null, secret: null },
  ]);
});

test("imports a key with its secret, refuses a name that exists and deletes a key", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto("/dns/keys");
  await page.getByTestId("dns-key-create").click();
  const form = page.getByTestId("dialog-key-form");
  await form.getByTestId("field-mode-import").check();
  await form.getByTestId("field-name").fill("xfr.example.test");
  await form.getByTestId("field-secret").fill("c2VjcmV0LXZhbHVlLW9mLWEtdGVzdA==");
  await form.getByTestId("form-submit").click();
  await expect(form.getByTestId("field-error")).toHaveAttribute("data-field", "name");
  await form.getByTestId("field-name").fill("peer.example.test");
  await form.getByTestId("form-submit").click();
  const shown = page.getByTestId("dialog-key-created");
  await expect(shown.getByTestId("key-secret")).toHaveText("c2VjcmV0LXZhbHVlLW9mLWEtdGVzdA==");
  await shown.getByTestId("key-stored").check();
  await shown.getByTestId("key-done").click();

  const row = gridRow(page, "dns-keys", "xfr.example.test");
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator('[data-key="delete"]').click();
  await page.getByTestId("dialog-key-delete").getByTestId("confirm-ok").click();
  await expect(row).toHaveCount(0);
  expect(fake.state.keys.map((k) => k.name)).toEqual(["peer.example.test"]);
});

test("does not offer the key pages to a viewer", async ({ page, api, signedIn }) => {
  void signedIn;
  await FakeDns.install(page);
  await signInAsViewer(api);
  await page.goto("/dns/acls");
  await expect(page.getByTestId("page-dns-acls")).toBeVisible();
  await expect(page.locator('[data-testid="dns-nav-link"][data-key="keys"]')).toHaveCount(0);
  await page.goto("/dns/keys");
  await expect(page.getByTestId("page-forbidden")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the keys page and the one-time secret in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeDns.install(page);
    await page.goto("/dns/keys");
    await expectRendered(page, page.getByTestId("page-dns-keys"), "sv", testInfo, "dns-keys");
    await page.getByTestId("dns-key-create").click();
    await page.getByTestId("dialog-key-form").getByTestId("field-name").fill("ddns.example.test");
    await page.getByTestId("dialog-key-form").getByTestId("form-submit").click();
    await expectRendered(page, page.getByTestId("dialog-key-created"), "sv", testInfo, "dns-key-created");
  });
});
