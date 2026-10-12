// WP3.11b: the vault page (IAM-15; docs/secrets.md, the key-encryption key): the key of the
// controller that answers, how every controller protects its key, the generations, and the
// online rotation from the page, which the leader runs in phases while the page follows it.
//
// Arrangement: the test server runs the `file` provider (support/server.ts), a plain key file,
// which the page marks weak with the warning `vault.kek.weak`. The setup session is fresh, so the
// rotation needs no new sign-in; the refusal after five minutes (`auth.step_up_required`) is
// covered by the component tests, since it needs a session older than that.

import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import type { Schemas } from "./support/api";

type KekStatus = Schemas["KekStatusView"];

test("shows the key of the controller and rotates it online", async ({ page, api, signedIn }) => {
  void signedIn;
  const before = await api.get<KekStatus>("/system/kek");
  await page.goto("/settings/vault");
  await expect(page.getByTestId("page-vault")).toBeVisible();
  const key = page.getByTestId("vault-key");
  await expect(key.getByTestId("vault-provider")).toHaveText("Key file");
  await expect(key.getByTestId("vault-protection")).toHaveAttribute("data-code", before.protection.code);
  await expect(key.getByTestId("vault-active")).toHaveText(before.active);
  await expect(page.getByTestId("vault-warning").first()).toHaveAttribute("data-code", "vault.kek.weak");
  await expect(page.getByTestId("vault-generation")).toHaveCount(before.generations.length);
  await expect(page.getByTestId("vault-controller")).toHaveCount(before.controllers.length);

  await page.getByTestId("vault-rotate").click();
  const dialog = page.getByTestId("dialog-confirm");
  await expect(dialog).toContainText("five minutes");
  await dialog.getByTestId("confirm-ok").click();
  await expect(page.getByTestId("vault-rotation-state")).toBeVisible();
  await expect(page.getByTestId("vault-rotation-state")).toHaveAttribute("data-phase", "done", { timeout: 60_000 });
  await expect(key.getByTestId("vault-active")).not.toHaveText(before.active);

  const after = await api.get<KekStatus>("/system/kek");
  expect(after.epoch).toBeGreaterThan(before.epoch);
  expect(after.rotation?.phase).toBe("done");
  await expect(key.getByTestId("vault-active")).toHaveText(after.active);
  await expect(key.getByTestId("vault-epoch")).toHaveText(String(after.epoch));
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the vault page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/vault");
    await expect(page.getByTestId("vault-key")).toBeVisible();
    await expect(page.getByTestId("vault-provider")).toHaveText("Nyckelfil");
    await expectRendered(page, page.getByTestId("page-vault"), "sv", testInfo, "vault");
  });
});
