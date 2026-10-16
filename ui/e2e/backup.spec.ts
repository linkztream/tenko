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
// - WP3.8a, the state of the backups: after a backup the age of the last good one is shown and
//   nothing warns; a backup that cannot be written (the target directory lies below a file) is
//   recorded as failed with its error code, warns with `backup.failed` and leaves no good backup.
//   The server cannot age a backup by days and the Lab profile does not warn, so the scenarios
//   for a backup nine days old (`backup.stale`), a failed run after an older good one and an
//   installation started from a restore answer `GET /system/backups` in the browser with a
//   made-up history over the real settings (`fakeHistory`). Swedish: the stale and failed states.

import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
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

// WP3.8a: the state of the backups on the page (OPS-07; docs/backup.md, sections 5 and 8): the age
// of the last good backup and the conditions to look at.

test("OPS-07: after a backup the page shows the age of the last good backup, no failure and no schedule", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-last-good")).toHaveText("Never");
  // Without a backup there is no age and nothing to warn about (the Lab profile does not warn).
  await expect(page.getByTestId("backup-age")).toHaveCount(0);
  await expect(page.getByTestId("backup-last-failed")).toHaveCount(0);
  await expect(page.getByTestId("backup-warnings")).toHaveCount(0);
  await expect(page.getByTestId("backup-next")).toHaveText("Not scheduled");

  await page.getByTestId("backup-now").click();
  const dialog = page.getByTestId("dialog-backup");
  await dialog.getByTestId("field-passphrase").fill(PASSPHRASE);
  await dialog.getByTestId("field-passphrase-again").fill(PASSPHRASE);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden({ timeout: 60_000 });

  // The age is the server's count of seconds since the last good backup, in its largest whole unit.
  const status = await api.get<Status>("/system/backups");
  expect(status.last_good).toBeTruthy();
  expect(status.age_seconds ?? -1).toBeGreaterThanOrEqual(0);
  expect(status.age_seconds ?? 9e9).toBeLessThan(120);
  await expect(page.getByTestId("backup-age")).toHaveText(/^\d+\s*(s|sec|secs|seconds?|min|minutes?)\b/);
  await expect(page.getByTestId("backup-last-good")).not.toHaveText("Never");
  await expect(page.getByTestId("backup-last-failed")).toHaveCount(0);
  await expect(page.getByTestId("backup-warnings")).toHaveCount(0);
  await expect(page.getByTestId("backup-running")).toHaveText("No");
});

test("OPS-07: a backup that cannot be written shows as failed, with its error code, a warning and no good backup", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  void signedIn;
  // A file where the parent of the target directory should be: the directory cannot be created.
  const blocker = join(server.dataDir, "not-a-directory");
  await writeFile(blocker, "a file, not a directory");
  const target = join(blocker, "backups");
  const current = (await api.get<Status>("/system/backups")).settings;
  await api.put("/system/backups/settings", {
    enabled: false,
    include_config: current.include_config,
    interval_hours: current.interval_hours,
    keep: current.keep,
    recipient: null,
    target_dir: target,
  });

  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-target")).toHaveText(target);
  await page.getByTestId("backup-now").click();
  const dialog = page.getByTestId("dialog-backup");
  await dialog.getByTestId("field-passphrase").fill(PASSPHRASE);
  await dialog.getByTestId("field-passphrase-again").fill(PASSPHRASE);
  await dialog.getByTestId("form-submit").click();

  // The run is recorded as failed, with the code the server gave it.
  const run = page.getByTestId("backup-run");
  await expect(run).toHaveCount(1, { timeout: 60_000 });
  await expect(run).toHaveAttribute("data-outcome", "failed");
  const status = await api.get<Status>("/system/backups");
  expect(status.last_good ?? null).toBeNull();
  expect(status.last_failed?.error?.code).toBeTruthy();
  const code = status.last_failed!.error!.code;
  await expect(run.getByTestId("backup-run-error")).toHaveAttribute("data-code", code);
  await expect(run.getByTestId("backup-restore-open")).toHaveCount(0);
  await expect(page.getByTestId("backup-last-failed")).toContainText(code);
  await expect(page.getByTestId("backup-last-good")).toHaveText("Never");
  await expect(page.getByTestId("backup-age")).toHaveCount(0);
  await expect(page.getByTestId("backup-warning").and(page.locator('[data-code="backup.failed"]'))).toHaveCount(1);
  expect(status.warnings.map((w) => w.code)).toContain("backup.failed");
  // The button is available again: the failure does not leave the page waiting.
  await expect(page.getByTestId("backup-now")).toBeEnabled();
  await expect(page.getByTestId("backup-running")).toHaveText("No");
});

/**
 * Answers `GET /system/backups` with the real settings and a made-up history, since the real
 * server cannot age a backup by days and the Lab profile of the test server does not warn.
 */
async function fakeHistory(page: Page, history: (real: Status) => Partial<Status>): Promise<void> {
  await page.route(/\/api\/v1\/system\/backups(\?|$)/, async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    const response = await route.fetch();
    const real = (await response.json()) as Status;
    await route.fulfill({ response, json: { ...real, ...history(real) } });
  });
}

function runOf(at: number, outcome: Run["outcome"], real: Status): Run {
  const finished = new Date(at).toISOString();
  return {
    id: "0190d1c2-0000-7000-8000-00000000b001",
    by: "system",
    bytes: outcome === "succeeded" ? 4_812_345 : null,
    file: outcome === "succeeded" ? "tenko-backup-20261007T000000Z-n1.tkbk" : null,
    finished_at: finished,
    job: null,
    node: 1,
    outcome,
    reason: "scheduled",
    revision: 1,
    slots: ["recipient"],
    started_at: new Date(at - 2_000).toISOString(),
    target_dir: real.settings.effective_target_dir,
    ...(outcome === "failed" ? { error: { code: "backup.target.unwritable", detail: "the target directory is not writable" } } : {}),
  } as unknown as Run;
}

test("OPS-07: a last good backup nine days old shows its age and the stale warning (faked status: the server cannot age a backup)", async ({
  page,
  signedIn,
}) => {
  void signedIn;
  const nineDays = 9 * 86_400;
  await fakeHistory(page, (real) => {
    const good = runOf(Date.now() - nineDays * 1000, "succeeded", real);
    return {
      last_good: good,
      age_seconds: nineDays,
      recent: [good],
      warnings: [{ code: "backup.stale", detail: "the last good backup is more than 7 days old", params: { days: "7" } }],
    };
  });
  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-age")).toHaveText(/^9\b/);
  const warning = page.getByTestId("backup-warning");
  await expect(warning).toHaveCount(1);
  await expect(warning).toHaveAttribute("data-code", "backup.stale");
  await expect(warning).toContainText("7");
  await expect(page.getByTestId("backup-last-good")).not.toHaveText("Never");
  await expect(page.getByTestId("backup-last-failed")).toHaveCount(0);
  await expect(page.getByTestId("backup-run")).toHaveCount(1);
  await expect(page.getByTestId("backup-run")).toHaveAttribute("data-outcome", "succeeded");
});

test("OPS-07: a failed scheduled run after an older good one shows both, the failure as a warning (faked status)", async ({ page, signedIn }) => {
  void signedIn;
  await fakeHistory(page, (real) => {
    const good = runOf(Date.now() - 3 * 86_400_000, "succeeded", real);
    const failed = { ...runOf(Date.now() - 3_600_000, "failed", real), id: "0190d1c2-0000-7000-8000-00000000b002" };
    return {
      last_good: good,
      last_failed: failed,
      age_seconds: 3 * 86_400,
      recent: [failed, good],
      warnings: [{ code: "backup.failed", detail: "the last backup failed: the target directory is not writable", params: { at: failed.finished_at, error: "backup.target.unwritable" } }],
    };
  });
  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-age")).toHaveText(/^3\b/);
  await expect(page.getByTestId("backup-last-failed")).toContainText("backup.target.unwritable");
  await expect(page.getByTestId("backup-warning")).toHaveAttribute("data-code", "backup.failed");
  const runs = page.getByTestId("backup-run");
  await expect(runs).toHaveCount(2);
  await expect(runs.nth(0)).toHaveAttribute("data-outcome", "failed");
  await expect(runs.nth(1)).toHaveAttribute("data-outcome", "succeeded");
  // Only the good backup has a restore command.
  await expect(runs.nth(0).getByTestId("backup-restore-open")).toHaveCount(0);
  await expect(runs.nth(1).getByTestId("backup-restore-open")).toBeVisible();
});

test("OPS-07: an installation started from a restore says so, with the file and the revision (faked status)", async ({ page, signedIn }) => {
  void signedIn;
  await fakeHistory(page, () => ({
    restored: {
      file: "tenko-backup-20261001T000000Z-n1.tkbk",
      backup_created_at: "2026-10-01T00:00:00Z",
      restored_at: "2026-10-12T08:00:00Z",
      started_at: "2026-10-12T08:00:00Z",
      node: 2,
      source_node: 1,
      revision: 4711,
    } as unknown as Status["restored"],
    warnings: [{ code: "backup.restored", detail: "the installation was started from a restore; take a backup", params: {} }],
  }));
  await page.goto("/settings/backup");
  const restored = page.getByTestId("backup-restored");
  await expect(restored).toBeVisible();
  await expect(restored).toContainText("tenko-backup-20261001T000000Z-n1.tkbk");
  await expect(restored).toContainText("4,711");
  await expect(page.getByTestId("backup-warning")).toHaveAttribute("data-code", "backup.restored");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("OPS-07: renders the stale and failed states of the backup page in Swedish (faked status)", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await fakeHistory(page, (real) => {
      const good = runOf(Date.now() - 9 * 86_400_000, "succeeded", real);
      const failed = { ...runOf(Date.now() - 3_600_000, "failed", real), id: "0190d1c2-0000-7000-8000-00000000b002" };
      const warnings: Status["warnings"] = [
        { code: "backup.stale", detail: "the last good backup is more than 7 days old", params: { days: "7" } },
        { code: "backup.failed", detail: "the last backup failed", params: { at: failed.finished_at, error: "backup.target.unwritable" } },
      ];
      return { last_good: good, last_failed: failed, age_seconds: 9 * 86_400, recent: [failed, good], warnings };
    });
    await page.goto("/settings/backup");
    await expect(page.getByTestId("backup-warning")).toHaveCount(2);
    await expectRendered(page, page.getByTestId("page-backup"), "sv", testInfo, "backup-states");
  });

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
