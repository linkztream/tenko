// WP3.11b: the backup page (OPS-07, S3-Q11; slice-3 plan WP3.4b) against the real server.
//
// The routes of backups (`GET`/`POST /system/backups`, `GET`/`PUT /settings/backup`) come with
// WP3.4b, which runs in parallel; until it is merged the server answers 501 and these scenarios
// are `test.fixme`. The UI is built against the shapes of section 3 of the plan
// (settings/backup/model.ts) and tested against the mock; at merge the lead removes the `fixme`
// once the shapes are reconciled.
//
// Scenarios:
// - Back up now with a passphrase: the backup job runs, the file appears in the target directory
//   and in the list, and `tenko backup verify` accepts it with the same passphrase.
// - The restore preview of that backup: the manifest (version, data format, revision, audit head,
//   CA fingerprint, parts) matches `tenko backup verify`, and the restore command names the file.
// - A weekly schedule saved with the number of backups kept; without a recipient key file the
//   page says that scheduled backups need one.
// - The warning after 7 days without a good backup in Standard and Hardened.
// - Swedish: the page and its dialogs.

import { expect, test } from "./support/fixtures";

test.fixme("backs up now and previews the restore of the new backup (WP3.4b routes not merged)", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  await expect(page.getByTestId("backup-status")).toBeVisible();
  await page.getByTestId("backup-now").click();
  const dialog = page.getByTestId("dialog-backup");
  await dialog.getByTestId("field-passphrase").fill("lantern-quartz-harbor");
  await dialog.getByTestId("field-passphrase-again").fill("lantern-quartz-harbor");
  await dialog.getByTestId("form-submit").click();
  await expect(page.getByTestId("backup-file")).toHaveCount(1, { timeout: 60_000 });
  await page.getByTestId("backup-preview").click();
  await expect(page.getByTestId("backup-restore-command")).toContainText("tenko backup restore");
});

test.fixme("saves a weekly schedule (WP3.4b routes not merged)", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/backup");
  const form = page.getByTestId("backup-schedule");
  await form.getByTestId("field-schedule-weekly").check();
  await expect(form.getByTestId("backup-needs-recipient")).toBeVisible();
  await form.getByTestId("field-time").fill("03:15");
  await form.getByTestId("form-submit").click();
  await expect(page.getByText("Every")).toBeVisible();
});
