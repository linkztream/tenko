// WP3.11b: the backup page (OPS-07, S3-Q11; docs/backup.md) against the real server.
//
// Arrangement: the setup session is fresh, so a backup and a change of the settings need no new
// sign-in; the refusal after five minutes (`auth.step_up_required`) is covered by the component
// tests, since it needs a session older than that. The test server runs the Lab profile, which
// does not warn about a missing backup (`backup.stale` is for Standard and Hardened; the
// component tests cover it). The backups go to `backups/` in the data directory of the test
// server, which is removed with it.
//
// Scenarios:
// - Back up now with a passphrase typed twice: the run is in the list as a good manual backup
//   with its file and size, the API agrees, and the restore command names the file.
// - A weak or mistyped passphrase is refused in the dialog before anything is sent.
// - An interval schedule with a recipient, the number of backups kept and the target directory
//   is saved and shown again after a reload; the server's settings agree.
// - Enabling the schedule without a recipient is hinted and sends nothing; the server refuses it
//   as well (`backup.key.missing`).
// - The dialog works with the keyboard and keeps focus inside; axe finds nothing on the page
//   and in the dialog.
// - Swedish: the page and its dialog.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import { ApiError, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

type Status = Schemas["BackupStatusView"];
type Run = Schemas["BackupRunView"];

const PASSPHRASE = "lantern-quartz-harbor";
/** A recipient the server accepts: `tkbr1:` and 43 base64url characters (no key file behind it). */
const RECIPIENT = "tkbr1:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

test("backs up now with a passphrase and lists the run", async ({ page, api, signedIn }) => {
  void signedIn;
  const before = await api.get<Status>("/system/backups");
  expect(before.recent).toHaveLength(0);

  await page.goto("/settings/backup");
  await expect(page.getByTestId("page-backup")).toBeVisible();
  await expect(page.getByTestId("backup-last-good")).toHaveText("Never");
  await expect(page.getByTestId("backup-runs-empty")).toBeVisible();

  await page.getByTestId("backup-now").click();
  const dialog = page.getByTestId("dialog-backup");
  // A short and a mistyped passphrase are refused in the dialog.
  await dialog.getByTestId("field-passphrase").fill("short");
  await dialog.getByTestId("field-passphrase-again").fill("short");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-passphrase")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByTestId("field-passphrase").fill(PASSPHRASE);
  await dialog.getByTestId("field-passphrase-again").fill(`${PASSPHRASE}-typo`);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeVisible();
  expect((await api.get<Status>("/system/backups")).recent).toHaveLength(0);

  await dialog.getByTestId("field-passphrase-again").fill(PASSPHRASE);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden({ timeout: 60_000 });

  const row = page.getByTestId("backup-run");
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-outcome", "succeeded");
  await expect(row).toHaveAttribute("data-reason", "manual");
  await expect(row.getByTestId("backup-run-file")).toHaveText(/\.tkbk$/);
  await expect(page.getByTestId("backup-warning")).toHaveCount(0);
  await expect(page.getByTestId("backup-last-good")).not.toHaveText("Never");

  const after = await api.get<Status>("/system/backups");
  expect(after.recent).toHaveLength(1);
  const run: Run = after.recent[0]!;
  expect(run.outcome).toBe("succeeded");
  expect(run.slots).toEqual(["passphrase"]);
  expect(run.bytes ?? 0).toBeGreaterThan(0);
  expect(after.last_good?.id).toBe(run.id);
  expect(after.last_failed ?? null).toBeNull();
  await expect(row.getByTestId("backup-run-file")).toHaveText(run.file ?? "");

  // Restore is a command on a new host, not a button.
  await row.getByTestId("backup-restore-open").click();
  const restore = page.getByTestId("dialog-backup-restore");
  await expect(restore.getByTestId("backup-restore-command")).toContainText("tenko backup restore");
  await expect(restore.getByTestId("backup-restore-command")).toContainText(run.file ?? "");
  await restore.getByTestId("form-cancel").click();
  await expect(restore).toBeHidden();
});

test("saves an interval schedule with a recipient and shows it after a reload", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  const form = page.getByTestId("backup-schedule");
  await expect(form.getByTestId("field-enabled")).not.toBeChecked();
  await expect(page.getByTestId("backup-next")).not.toHaveText(/\d{4}/);

  await form.getByTestId("field-enabled").check();
  await form.getByTestId("field-recipient").fill(RECIPIENT);
  await form.getByTestId("field-interval").fill("12");
  await form.getByTestId("field-keep").fill("14");
  await form.getByTestId("field-include-config").uncheck();
  await form.getByTestId("form-submit").click();
  await expect(form.getByTestId("field-recipient")).toHaveValue(RECIPIENT);

  await expect.poll(async () => (await api.get<Status>("/system/backups")).settings.keep).toBe(14);
  const stored = (await api.get<Status>("/system/backups")).settings;
  expect(stored).toMatchObject({ enabled: true, interval_hours: 12, keep: 14, recipient: RECIPIENT, include_config: false });

  await page.reload();
  const reloaded = page.getByTestId("backup-schedule");
  await expect(reloaded.getByTestId("field-enabled")).toBeChecked();
  await expect(reloaded.getByTestId("field-interval")).toHaveValue("12");
  await expect(reloaded.getByTestId("field-keep")).toHaveValue("14");
  await expect(reloaded.getByTestId("field-recipient")).toHaveValue(RECIPIENT);
  await expect(reloaded.getByTestId("field-include-config")).not.toBeChecked();
  await expect(reloaded.getByTestId("backup-needs-recipient")).toBeHidden();
});

test("enabling the schedule without a recipient is hinted and refused", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  const form = page.getByTestId("backup-schedule");
  await form.getByTestId("field-enabled").check();
  await expect(form.getByTestId("backup-needs-recipient")).toBeVisible();
  await form.getByTestId("form-submit").click();
  await expect(form.getByTestId("backup-needs-recipient")).toBeVisible();
  expect((await api.get<Status>("/system/backups")).settings.enabled).toBe(false);

  // The server refuses it as well, whatever the page does.
  const current = (await api.get<Status>("/system/backups")).settings;
  const error = await api
    .put("/system/backups/settings", {
      enabled: true,
      include_config: current.include_config,
      interval_hours: current.interval_hours,
      keep: current.keep,
      recipient: null,
      target_dir: null,
    })
    .then(
      () => null,
      (err: unknown) => err,
    );
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).code).toBe("backup.key.missing");
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

test("the backup dialog works with the keyboard, keeps focus inside and passes axe", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-status")).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-backup']")).toEqual([]);
  await page.getByTestId("backup-now").focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByTestId("dialog-backup");
  await expect(dialog).toBeVisible();
  expect(await axeViolations(page, "[data-testid='dialog-backup']")).toEqual([]);
  for (let i = 0; i < 12; i += 1) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest("[data-testid='dialog-backup']"))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("backup-now")).toBeFocused();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the backup page and its dialog in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/backup");
    await expect(page.getByTestId("backup-status")).toBeVisible();
    await expect(page.getByTestId("backup-last-good")).toHaveText("Aldrig");
    await expectRendered(page, page.getByTestId("page-backup"), "sv", testInfo, "backup");
    await page.getByTestId("backup-now").click();
    await expectRendered(page, page.getByTestId("dialog-backup"), "sv", testInfo, "backup-dialog");
  });
});
