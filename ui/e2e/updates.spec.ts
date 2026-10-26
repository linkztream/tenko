// Updates from the UI, end to end (WP2.11; OPS-24, TGL-23, NEVER-02; docs/upgrades.md sections
// 6.3, 8 and 9.1). The page /updates, the update notice in the status bar and on the dashboard, the
// install job with its four steps and its dry run, the restart into the new version, "what is
// new" after the upgrade, and a dry run that refuses the new binary.
//
// Arrangement: a release source of the test on the loopback (support/release.ts) answers
// /releases.json with the manifest the test sets and serves this very build as the release
// file of the next version. A server started from the version layout (`tenko upgrade layout`,
// supervised) installs that file; debug builds started with TENKO_TEST_VERSION_FROM_LAYOUT=1
// take their version from the layout directory, so the copy reports the next version. The
// test plays the service manager: it waits for the exit with status 12 and starts the server
// again. Everything else is checked in the UI and through the public API.
//
// - Air gap: a server without a source has the check off, answers a check on demand with 409
//   `update.check_off` and takes the release list as an uploaded file (docs 8.8).
// - Check and notice: "check now" asks the source with `User-Agent: tenko/<version>`; the
//   notice shows in the status bar, on the dashboard card and on /updates, where the release
//   card renders the Markdown notes as elements (never as markup) with the marks and the
//   action the release asks for; a server that is not run from the layout shows why it
//   cannot install (docs 8.4).
// - The backup before an install (ADR 0023, docs 8.12): the install test answers "Backup now"
//   with a passphrase (the backup is recorded `before_update` and the install goes without an
//   answer), the refused dry run answers "No, don't back up" (audited `skipped`), and after it
//   the one-hour rule: an install with no answer is refused with 409 `update.backup_required`
//   until a backup is taken, then the dialog says it is recent and asks nothing.
// - Install: confirmation that repeats the action, the four steps (fetch, verify, the dry run
//   `sys.update.check`, switch), exit with status 12, restart, the UI reloads into the new
//   version, "what is new" for the administrator, the confirmed attempt, the job page and the
//   audit record `sys.update.confirm`.
// - Refused dry run: the new binary reports another version than the manifest, the job fails
//   at `sys.update.check`, rolls back, the attempt is `failed`, the server keeps running.
// - Swedish: /updates with notes and marks rendered with no message key showing.
//
// What stays manual: a real service manager (systemd, the Windows service) and the probation
// switch back of a new version that does not start (Rust test crates/tenko/tests/upgrade_install.rs);
// the checksum mismatch (same Rust test); the step-up sign-in of Standard and Hardened and the
// upload of a release file in the browser (an 89 MB body; the install steps are the same);
// containers and clusters (docs 8.9, 8.10); signed releases (API-19, not enforced yet).

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { test as base, expect } from "./support/fixtures";
import { ApiError, type Api, type Schemas } from "./support/api";
import { expectRendered } from "./support/i18n";
import { buildAsset, nextPatch, ReleaseSource, type Manifest, type ManifestRelease } from "./support/release";
import { cell, gridRow, withIndex, withKey } from "./support/ui";

type UpdateStatus = Schemas["UpdateStatus"];
type WhatsNew = Schemas["WhatsNew"];
type JobDetail = Schemas["JobDetail"];
type Audit = Schemas["Page_AuditRecord"];

/** What the server of a test is set up as. */
type Scenario =
  /** No release source: the default of every test server. */
  | "air-gapped"
  /** A release source, run from the build: the check works, an install is blocked. */
  | "source"
  /** A release source, run from the version layout as a supervised service. */
  | "install"
  /** Like `install`, but the copy reports the old version, so the dry run refuses it. */
  | "mismatch";

const test = base.extend<{ source: ReleaseSource; scenario: Scenario }>({
  scenario: ["source", { option: true }],
  // Playwright needs the destructuring pattern to see that the fixture depends on nothing.
  // eslint-disable-next-line no-empty-pattern
  source: async ({}, use) => {
    const source = await ReleaseSource.start();
    try {
      await use(source);
    } finally {
      await source.stop();
    }
  },
  serverOptions: async ({ source, scenario }, use) => {
    if (scenario === "air-gapped") {
      await use({});
      return;
    }
    const updates = { sourceUrl: source.manifestUrl, readyTimeoutSecs: 60 };
    await use(scenario === "source" ? { updates } : { updates, layout: true, versionFromLayout: scenario === "install" });
  },
});

/** The four steps of the install job, in order (docs 8.5). */
const STEPS = ["sys.update.fetch", "sys.update.verify", "sys.update.check", "sys.update.switch"] as const;

/** Notes in Markdown: three sections, inline marks, and markup that must stay text. */
const NOTES = [
  "### Added",
  "",
  "- Subnet **templates** for new prefixes.",
  "- Lease reports per VLAN.",
  "",
  "### Fixed",
  "",
  "- The report no longer lists 203.0.113.9 twice.",
  "",
  "### Security",
  "",
  "- Session cookies are marked `HttpOnly`.",
  '- Markup such as <img src="x" onerror="window.pwned = 1"> in the notes stays text.',
].join("\n");

/** What the operator must do; the command is inline code. */
const ACTION = "Stop the DHCP relay on 192.0.2.1 and run `tenko upgrade check` before the restart.";

async function updateStatus(api: Api): Promise<UpdateStatus> {
  return api.get<UpdateStatus>("/system/updates");
}

/** The error a request ends with. */
async function failure(request: Promise<unknown>): Promise<ApiError> {
  try {
    await request;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("the request was expected to fail");
}

/** A release of the manifest with the notes, the marks and the action of this file. */
function release(version: string, assets: ManifestRelease["assets"]): ManifestRelease {
  return { version, date: "2026-10-10", notes: NOTES, security: true, requires_action: true, action: ACTION, assets };
}

function manifestOf(...releases: ManifestRelease[]): Manifest {
  return { schema: 1, project: "tenko", releases };
}

/** The asset of this build for `version`, served by `source`, as the manifest lists it. */
async function offerBuild(source: ReleaseSource, version: string): Promise<ManifestRelease["assets"]> {
  const { path, ...asset } = await buildAsset(version);
  source.serveFile(asset.name, path);
  return [asset];
}

/** A passphrase of the backup before an update; the e2e server has no backup recipient. */
const BACKUP_PASSPHRASE = "a long backup passphrase for the update test";

/**
 * Answers the open install dialog and returns what the server answered: the job and the
 * version, with the body the install was sent with. `recent`: the dialog says a backup is
 * recent and is confirmed; `skip`: "No, don't back up"; `backup`: "Backup now" with a
 * passphrase, which writes the backup first.
 */
async function confirmInstall(
  page: Page,
  answer: "recent" | "skip" | "backup",
): Promise<{ started: Schemas["InstallStarted"]; body: Record<string, unknown> }> {
  const dialog = page.getByTestId("dialog-update-install");
  if (answer === "recent") {
    await expect(dialog.getByTestId("update-backup-recent")).toBeVisible();
  } else {
    await expect(dialog.getByTestId("update-backup-question")).toBeVisible();
    await expect(dialog.getByTestId("update-backup-now")).toBeFocused();
  }
  if (answer === "backup") {
    await dialog.getByTestId("update-backup-passphrase").fill(BACKUP_PASSPHRASE);
    await dialog.getByTestId("update-backup-passphrase-again").fill(BACKUP_PASSPHRASE);
  }
  const button = { recent: "confirm-ok", skip: "update-backup-skip", backup: "update-backup-now" }[answer];
  const [response] = await Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/system/updates/install" && r.request().method() === "POST", {
      timeout: 60_000,
    }),
    dialog.getByTestId(button).click(),
  ]);
  expect(response.status()).toBe(202);
  return {
    started: (await response.json()) as Schemas["InstallStarted"],
    body: response.request().postDataJSON() as Record<string, unknown>,
  };
}

/** The newest `sys.update.install` record: what was decided about the backup. */
async function installAudit(api: Api): Promise<Record<string, string>> {
  let context: Record<string, string> | undefined;
  await expect
    .poll(async () => {
      const audit = await api.get<Audit>("/audit", { action: "sys.update.install" });
      context = audit.items[0]?.draft.details?.context ?? undefined;
      return context !== undefined;
    }, { message: "the audit record of the install" })
    .toBe(true);
  return context!;
}

/** The job as the API has it, once it is final. */
async function finalJob(api: Api, id: string): Promise<JobDetail> {
  return api.waitForJob(id, 90_000);
}

test.describe("without a release source", () => {
  test.use({ scenario: "air-gapped" });

  test("an air-gapped server has the check off, refuses a check and takes the release list as a file", async ({
    page,
    api,
    signedIn,
  }) => {
    expect(signedIn.session.user.name).toBe("admin");
    const before = await updateStatus(api);
    expect(before.check.enabled).toBe(false);
    expect(before.check.off_reason).toBe("air_gapped");
    expect(before.update_available).toBe(false);
    expect(before.releases).toEqual([]);

    // "Check now" is answered with 409 `update.check_off`.
    const refused = await failure(api.post("/system/updates/check"));
    expect(refused.status).toBe(409);
    expect(refused.code).toBe("update.check_off");

    // The page shows the running version, the check off and the upload path; the button is not usable.
    await page.goto("/updates");
    await expect(page.getByTestId("page-updates")).toBeVisible();
    await expect(page.getByTestId("updates-running-version")).toHaveText(before.running);
    await expect(page.getByTestId("updates-check-state")).toHaveAttribute("data-key", "off");
    await expect(page.getByTestId("updates-check")).toBeDisabled();
    await expect(page.getByTestId("updates-uptodate")).toBeVisible();
    await expect(page.getByTestId("update-release")).toHaveCount(0);
    await expect(page.getByTestId("status-update")).toHaveCount(0);
    const upload = page.getByTestId("updates-upload-panel");
    await expect(upload).toBeVisible();
    await expect(upload.getByTestId("updates-manifest-file")).toBeVisible();
    await expect(upload.getByTestId("updates-manifest-upload")).toBeDisabled();
    await expect(upload.getByTestId("updates-upload-wait")).toBeVisible();

    // The release list of a newer version, chosen as a file: the page shows it and the notice follows.
    const next = nextPatch(before.running);
    const list = manifestOf(
      release(next, [
        {
          platform: before.platform,
          name: `tenko-${next}-${before.platform}`,
          url: `tenko-${next}-${before.platform}`,
          sha256: "0".repeat(64),
          size: 1_000_000,
        },
      ]),
    );
    await upload.getByTestId("updates-manifest-file").setInputFiles({
      name: "releases.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(list)),
    });
    await expect(upload.getByTestId("updates-manifest-upload")).toBeEnabled();
    await upload.getByTestId("updates-manifest-upload").click();
    const card = withKey(page.getByTestId("updates-releases"), "update-release", next);
    await expect(card).toBeVisible();
    await expect(page.getByTestId("updates-manifest-info")).toHaveAttribute("data-key", "uploaded");
    await expect(page.getByTestId("updates-newest")).toHaveText(next);
    await expect(page.getByTestId("status-update")).toContainText(next);
    await expect(page.getByTestId("updates-check")).toBeDisabled();

    // Not run from the layout: the page says why it cannot install, as the API does.
    const after = await updateStatus(api);
    expect(after.update_available).toBe(true);
    expect(after.latest).toBe(next);
    expect(after.manifest?.origin).toBe("uploaded");
    expect(after.install.from_source).toBe(false);
    expect(after.install.from_source_blocked).toBeTruthy();
    await expect(page.getByTestId("updates-blocked-reason")).toHaveAttribute("data-key", after.install.from_source_blocked!);
    await expect(page.getByTestId("updates-install")).toHaveCount(0);

    // The upload is a decision of an administrator: it is audited with the newest version (NEVER-02).
    const audit = await api.get<Audit>("/audit", { action: "sys.update.manifest" });
    expect(audit.items).toHaveLength(1);
    expect(audit.items[0]!.principal).toMatchObject({ kind: "user", id: signedIn.session.user.id });
    expect(audit.items[0]!.draft.details?.context).toEqual({ latest: next });
  });
});

test.describe("with a release source", () => {
  test("a check asks the source, and the notice, the notes and the marks show where an administrator looks", async ({
    page,
    api,
    source,
    signedIn,
  }) => {
    expect(signedIn.session.user.name).toBe("admin");
    const status = await updateStatus(api);
    const running = status.running;
    const next = nextPatch(running);
    expect(status.check.enabled).toBe(true);
    expect(status.check.source).toBe(source.manifestUrl);
    expect(status.update_available).toBe(false);

    await page.goto("/updates");
    await expect(page.getByTestId("page-updates")).toBeVisible();
    await expect(page.getByTestId("updates-running-version")).toHaveText(running);
    await expect(page.getByTestId("updates-check-state")).toHaveAttribute("data-key", "on");
    await expect(page.getByTestId("updates-source")).toHaveText(source.manifestUrl);
    // A loopback test source is no code host: there is no release page to link to. The status bar links the version.
    await expect(page.getByTestId("release-notes-link")).toHaveCount(0);
    await expect(page.getByTestId("status-version")).toHaveAttribute("href", "/updates");
    await expect(page.getByTestId("updates-uptodate")).toBeVisible();
    await expect(page.getByTestId("status-update")).toHaveCount(0);

    // A source with nothing to offer: the check fails and the page says which code it failed with.
    source.manifest = null;
    await page.getByTestId("updates-check").click();
    await expect(page.getByTestId("updates-last-error")).toHaveAttribute("data-code", "update.fetch_failed");
    expect((await updateStatus(api)).check.last_error).toBe("update.fetch_failed");
    await expect(page.getByTestId("update-release")).toHaveCount(0);

    // The source offers the next version: security fixes and an action the operator must take.
    source.manifest = manifestOf(release(next, []));
    await page.getByTestId("updates-check").click();
    const card = withKey(page.getByTestId("updates-releases"), "update-release", next);
    await expect(card).toBeVisible();
    await expect(page.getByTestId("updates-last-error")).toHaveCount(0);
    expect(source.requests.length).toBeGreaterThanOrEqual(2);
    for (const request of source.requests) {
      expect(request.path).toBe("/releases.json");
      expect(request.userAgent).toBe(`tenko/${running}`);
    }

    const found = await updateStatus(api);
    expect(found.update_available).toBe(true);
    expect(found.latest).toBe(next);
    expect(found.security).toBe(true);
    expect(found.requires_action).toBe(true);
    expect(found.check.last_error ?? null).toBeNull();
    expect(found.manifest?.origin).toBe("fetched");
    await expect(page.getByTestId("updates-manifest-info")).toHaveAttribute("data-key", "fetched");
    await expect(page.getByTestId("updates-newest")).toHaveText(next);

    // The notes are elements: three headings, the list items, bold and code inside them.
    const headings = card.getByTestId("md-heading");
    await expect(headings).toHaveText(["Added", "Fixed", "Security"]);
    await expect(headings.first()).toHaveAttribute("data-level", "4");
    const items = card.getByTestId("md-item");
    await expect(items).toHaveCount(5);
    await expect(items.getByTestId("md-strong")).toHaveText("templates");
    await expect(items.getByTestId("md-code")).toHaveText("HttpOnly");
    // Markup in the notes is text: no image, no script ran.
    await expect(card.locator("img")).toHaveCount(0);
    expect(await page.evaluate(() => "pwned" in window)).toBe(false);

    // The marks and the action of the release.
    await expect(withKey(card, "update-mark", "security")).toBeVisible();
    await expect(withKey(card, "update-mark", "action")).toBeVisible();
    const action = card.getByTestId("update-action");
    await expect(action).toBeVisible();
    await expect(action.getByTestId("md-code")).toHaveText("tenko upgrade check");
    await expect(action).toContainText("192.0.2.1");

    // The notice in the status bar follows the check, and its link leads to this page.
    const notice = page.getByTestId("status-update");
    await expect(notice).toBeVisible();
    await expect(notice).toContainText(next);
    await expect(notice).toHaveAttribute("href", "/updates");

    // This server does not run from the layout, so it cannot install: the page gives the reason.
    expect(found.install.from_source).toBe(false);
    const blocked = found.install.from_source_blocked;
    expect(blocked).toBeTruthy();
    await expect(page.getByTestId("updates-blocked-reason")).toHaveAttribute("data-key", blocked!);
    await expect(page.getByTestId("updates-install")).toHaveCount(0);

    // The dashboard card names the version, carries the marks and opens the page.
    await page.goto("/");
    const dashboard = page.getByTestId("dashboard-update");
    await expect(dashboard).toBeVisible();
    await expect(dashboard).toContainText(next);
    await expect(withKey(dashboard, "update-mark", "security")).toBeVisible();
    await expect(withKey(dashboard, "update-mark", "action")).toBeVisible();
    await expect(page.getByTestId("status-update")).toBeVisible();
    await dashboard.getByTestId("dashboard-update-open").click();
    await expect(page).toHaveURL(/\/updates$/);
    await expect(page.getByTestId("page-updates")).toBeVisible();
    await expect(card).toBeVisible();
  });

  test.describe("in Swedish", () => {
    test.use({ locale: "sv-SE" });

    test("the updates page shows no message key, with a failed check and with notes and marks", async ({
      page,
      api,
      source,
      signedIn,
    }, testInfo) => {
      expect(signedIn.session.user.name).toBe("admin");
      const running = (await updateStatus(api)).running;
      const next = nextPatch(running);

      await page.goto("/updates");
      const root = page.getByTestId("page-updates");
      await expectRendered(page, root, "sv", testInfo, "updates-check");

      // The failed check, with the code of the source's answer.
      source.manifest = null;
      await page.getByTestId("updates-check").click();
      await expect(page.getByTestId("updates-last-error")).toHaveAttribute("data-code", "update.fetch_failed");
      await expectRendered(page, root, "sv", testInfo, "updates-failed-check");

      // The release with its marks and its action; the notes themselves stay English.
      source.manifest = manifestOf(release(next, []));
      await page.getByTestId("updates-check").click();
      const card = withKey(page.getByTestId("updates-releases"), "update-release", next);
      await expect(card).toBeVisible();
      await expect(withKey(card, "update-mark", "security")).toBeVisible();
      await expect(withKey(card, "update-mark", "action")).toBeVisible();
      await expect(page.getByTestId("updates-blocked-reason")).toBeVisible();
      await expectRendered(page, root, "sv", testInfo, "updates-release");
    });
  });
});

test.describe("from the version layout", () => {
  test.use({ scenario: "install" });

  test("an install runs fetch, verify, the dry run and the switch, restarts into the new version and shows what is new", async ({
    page,
    api,
    server,
    source,
    signedIn,
  }) => {
    expect(signedIn.session.user.name).toBe("admin");
    const status = await updateStatus(api);
    const running = status.running;
    const next = nextPatch(running);
    expect(status.install.policy).toBe("ui");
    source.manifest = manifestOf(release(next, await offerBuild(source, next)));

    // A user with no recorded version sees nothing. The administrator then records the notes of the
    // running version as seen, so the notes of the next one are new to them.
    expect((await api.get<WhatsNew>("/system/updates/whats-new")).show).toBe(false);
    await api.post<void>("/system/updates/whats-new/seen");
    const seen = await api.get<WhatsNew>("/system/updates/whats-new");
    expect(seen.running).toBe(running);
    expect(seen.last_seen).toBe(running);
    expect(seen.show).toBe(false);

    // Check now: this server runs from the layout, so the page offers the install.
    await page.goto("/updates");
    await expect(page.getByTestId("page-updates")).toBeVisible();
    await expect(page.getByTestId("updates-running-version")).toHaveText(running);
    await page.getByTestId("updates-check").click();
    await expect(withKey(page.getByTestId("updates-releases"), "update-release", next)).toBeVisible();
    expect((await updateStatus(api)).install.from_source).toBe(true);
    await expect(page.getByTestId("updates-blocked-reason")).toHaveCount(0);

    // The confirmation names the version and repeats the action of the release.
    await page.getByTestId("updates-install").click();
    const dialog = page.getByTestId("dialog-update-install");
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(next);
    const repeated = dialog.getByTestId("update-confirm-action");
    await expect(repeated).toBeVisible();
    await expect(repeated.locator(`[data-key="${next}"]`)).toBeVisible();
    await expect(repeated.getByTestId("md-code")).toHaveText("tenko upgrade check");
    await expect(repeated).toContainText("192.0.2.1");
    // The health probe names the version the server runs as, which the page waits for after
    // the restart: still the old one.
    expect((await api.get<Schemas["Health"]>("/health")).version).toBe(running);
    // No backup yet: the dialog asks for one first; "Backup now" asks for a passphrase (no
    // recipient is set up), writes the backup and then installs with no answer, as the backup
    // is now recent (ADR 0023, docs 8.12).
    await expect(dialog.getByTestId("update-backup-age")).toContainText("There is no backup yet");
    const { started: accepted, body } = await confirmInstall(page, "backup");
    expect(accepted.version).toBe(next);
    expect(body.backup).toBeUndefined();
    const job = accepted.job_id;
    const backups = await api.get<Schemas["BackupStatusView"]>("/system/backups");
    expect(backups.last_good?.reason).toBe("before_update");
    expect(backups.last_good?.before_update).toBe(next);
    expect(backups.last_good?.slots).toEqual(["passphrase"]);
    const decided = await installAudit(api);
    expect(decided.backup).toBe("recent");
    expect(decided.version).toBe(next);

    // The progress lists the four steps, the dry run is `sys.update.check`, up to the switch.
    const progress = page.getByTestId("updates-progress");
    await expect(progress).toBeVisible();
    await expect(progress.getByTestId("updates-step")).toHaveCount(STEPS.length);
    for (const kind of STEPS) {
      await expect(withKey(progress, "updates-step", kind)).toHaveAttribute("data-state", "done", { timeout: 90_000 });
    }
    await expect(progress).toHaveAttribute("data-state", "restarting");
    await expect(progress.getByTestId("updates-restarting")).toBeVisible();
    await expect(progress.getByTestId("updates-job-link")).toHaveAttribute("href", `/jobs/${job}`);

    // The server stops with status 12 and the service manager (this test) starts it again.
    expect(await server.waitForExit(90_000)).toBe(true);
    expect(server.exitCode).toBe(12);
    await server.restart();

    // The page asks the health probe every two seconds, sees the new version and reloads into it.
    await expect(page.getByTestId("updates-running-version")).toHaveText(next, { timeout: 60_000 });
    expect((await api.get<Schemas["Health"]>("/health")).version).toBe(next);
    await expect(page.getByTestId("updates-progress")).toHaveCount(0);

    // What is new: the notes of the version, shown once, recorded when closed.
    const unseen = await api.get<WhatsNew>("/system/updates/whats-new");
    expect(unseen.running).toBe(next);
    expect(unseen.last_seen).toBe(running);
    expect(unseen.show).toBe(true);
    expect(unseen.releases.map((r) => r.version)).toEqual([next]);
    const whatsNew = page.getByTestId("dialog-whats-new");
    await expect(whatsNew).toBeVisible();
    const notes = withKey(whatsNew.getByTestId("whats-new-notes"), "update-release", next);
    await expect(notes).toBeVisible();
    await expect(notes.getByTestId("md-heading")).toHaveText(["Added", "Fixed", "Security"]);
    await expect(withKey(notes, "update-mark", "security")).toBeVisible();
    await expect(withKey(notes, "update-mark", "action")).toBeVisible();
    await whatsNew.getByTestId("whats-new-close").click();
    await expect(whatsNew).toHaveCount(0);
    await expect
      .poll(async () => (await api.get<WhatsNew>("/system/updates/whats-new")).show, { message: "the acknowledgement is recorded" })
      .toBe(false);
    const acknowledged = await api.get<WhatsNew>("/system/updates/whats-new");
    expect(acknowledged.last_seen).toBe(next);

    // The new version runs, is up to date and confirmed the attempt.
    const after = await updateStatus(api);
    expect(after.running).toBe(next);
    expect(after.update_available).toBe(false);
    expect(after.attempt?.state).toBe("confirmed");
    expect(after.attempt?.from).toBe(running);
    expect(after.attempt?.to).toBe(next);
    expect(after.attempt?.job_id).toBe(job);
    await expect(page.getByTestId("updates-uptodate")).toBeVisible();
    await expect(page.getByTestId("updates-attempt")).toHaveCount(0);
    await expect(page.getByTestId("status-update")).toHaveCount(0);

    // The install job on its page: four steps, all done.
    const detail = await finalJob(api, job);
    expect(detail.job.state).toBe("succeeded");
    expect(detail.job.steps.map((s) => s.kind)).toEqual([...STEPS]);
    await page.goto(`/jobs/${job}`);
    await expect(page.getByTestId("page-job")).toBeVisible();
    await expect(page.getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");
    await expect(page.getByTestId("job-step")).toHaveCount(STEPS.length);
    for (const step of detail.job.steps) {
      await expect(withIndex(page, "job-step", step.index)).toHaveAttribute("data-state", "done");
    }
    await expect(page.getByTestId("job-error")).toHaveCount(0);

    // The new version audited the confirmation (NEVER-02), and the audit view lists it.
    await expect
      .poll(async () => (await api.get<Audit>("/audit", { action: "sys.update.confirm" })).items.length, {
        message: "the audit record of the confirmation",
      })
      .toBe(1);
    const record = (await api.get<Audit>("/audit", { action: "sys.update.confirm" })).items[0]!;
    expect(record.draft.details?.context).toEqual({ from: running, to: next, job });
    await page.goto("/audit");
    await page.getByTestId("audit-filter-action").fill("sys.update.confirm");
    const row = gridRow(page, "audit", String(record.seq));
    await expect(row).toBeVisible();
    await expect(cell(row, "action")).toContainText("sys.update.confirm");
  });
});

test.describe("from the version layout, with a copy that reports the old version", () => {
  test.use({ scenario: "mismatch" });

  test("a dry run that refuses the new binary fails the install, rolls it back and leaves the server running", async ({
    page,
    api,
    server,
    source,
    signedIn,
  }) => {
    expect(signedIn.session.user.name).toBe("admin");
    const running = (await updateStatus(api)).running;
    const next = nextPatch(running);
    source.manifest = manifestOf(release(next, await offerBuild(source, next)));

    await page.goto("/updates");
    await expect(page.getByTestId("page-updates")).toBeVisible();
    await page.getByTestId("updates-check").click();
    await expect(withKey(page.getByTestId("updates-releases"), "update-release", next)).toBeVisible();
    expect((await updateStatus(api)).install.from_source).toBe(true);
    // The age of the newest backup stands next to the button; there is none yet.
    await expect(page.getByTestId("updates-install-panel").getByTestId("updates-backup-age")).toContainText("No backup yet");
    await page.getByTestId("updates-install").click();
    // "No, don't back up": the install says skip and the audit record says so.
    const { started, body } = await confirmInstall(page, "skip");
    expect(body.backup).toBe("skip");
    const job = started.job_id;
    expect((await installAudit(api)).backup).toBe("skipped");

    // The job fails at the dry run: the page shows it on that step and not as a restart.
    const progress = page.getByTestId("updates-progress");
    await expect(progress).toHaveAttribute("data-state", "failed", { timeout: 90_000 });
    await expect(progress.getByTestId("updates-failed")).toBeVisible();
    await expect(progress.getByTestId("updates-restarting")).toHaveCount(0);
    await expect(withKey(progress, "updates-step", "sys.update.check")).toHaveAttribute("data-state", "failed");

    const detail = await finalJob(api, job);
    expect(detail.job.state).toBe("rolled_back");
    const code = detail.job.error?.code;
    expect(code).toBe("update.version_mismatch");
    // The download and the verification are undone, the dry run failed, the switch never ran.
    const expected = {
      "sys.update.fetch": "compensated",
      "sys.update.verify": "compensated",
      "sys.update.check": "failed",
      "sys.update.switch": "pending",
    };
    expect(Object.fromEntries(detail.job.steps.map((s) => [s.kind, s.state.state]))).toEqual(expected);
    for (const kind of STEPS) await expect(withKey(progress, "updates-step", kind)).toHaveAttribute("data-state", expected[kind]);

    // The job page shows the same states and the failure of the dry run on its step.
    await progress.getByTestId("updates-job-link").click();
    await expect(page).toHaveURL(new RegExp(`/jobs/${job}$`));
    await expect(page.getByTestId("page-job")).toBeVisible();
    await expect(page.getByTestId("job-state")).toHaveAttribute("data-state", "rolled_back");
    await expect(page.getByTestId("job-error")).toBeVisible();
    for (const step of detail.job.steps) {
      await expect(withIndex(page, "job-step", step.index)).toHaveAttribute("data-state", step.state.state);
    }
    const checkStep = detail.job.steps.find((s) => s.kind === "sys.update.check")!;
    await expect(withIndex(page, "job-step", checkStep.index).getByTestId("job-step-failure")).toBeVisible();

    // The attempt is `failed` with the code, the page shows it, and nothing was switched or restarted.
    await expect
      .poll(async () => (await updateStatus(api)).attempt?.state, { message: "the attempt record of the failed install" })
      .toBe("failed");
    const failed = await updateStatus(api);
    expect(failed.attempt?.reason).toBe(code);
    expect(failed.attempt?.from).toBe(running);
    expect(failed.attempt?.to).toBe(next);
    expect(failed.attempt?.job_id).toBe(job);
    expect(failed.running).toBe(running);
    expect(failed.update_available).toBe(true);
    expect(server.running).toBe(true);
    expect(server.exitCode).toBeUndefined();
    expect(existsSync(join(server.dataDir, "updates", next))).toBe(false);

    await page.goto("/updates");
    const attempt = page.getByTestId("updates-attempt");
    await expect(attempt).toBeVisible();
    await expect(attempt.locator("[data-code]")).toHaveAttribute("data-code", code!);
    await expect(page.getByTestId("updates-progress")).toHaveCount(0);
    await expect(page.getByTestId("updates-running-version")).toHaveText(running);
    // The release is still on offer: the administrator can try again once the file is right.
    await expect(page.getByTestId("updates-install")).toBeVisible();

    // The one-hour rule: an install without an answer is refused while no backup is recent;
    // after a backup the dialog says how old it is and asks nothing.
    const refused = await failure(api.post("/system/updates/install", { version: next }));
    expect(refused.status).toBe(409);
    expect(refused.code).toBe("update.backup_required");
    await api.post("/system/backups", { passphrase: BACKUP_PASSPHRASE });
    await page.goto("/updates");
    await expect(page.getByTestId("updates-install-panel").getByTestId("updates-backup-age")).toContainText("Last backup");
    await page.getByTestId("updates-install").click();
    const again = page.getByTestId("dialog-update-install");
    await expect(again.getByTestId("update-backup-recent")).toBeVisible();
    await expect(again.getByTestId("update-backup-question")).toHaveCount(0);
    await again.getByTestId("confirm-cancel").click();
    await expect(again).toHaveCount(0);
  });
});
