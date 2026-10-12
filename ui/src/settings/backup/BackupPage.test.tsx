import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../../api/client";
import { db } from "../../api/mock/db";
import { backupState } from "../../api/mock/routes-backup";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import BackupPage from "./BackupPage";
import {
  absoluteDir,
  ageText,
  draftErrors,
  draftOf,
  intervalText,
  needsRecipient,
  restoreCommand,
  scheduleText,
  settingsBody,
  sizeText,
  validRecipient,
} from "./model";

const NO_SHELL = { disable: ["region"] } as const;
/** A documentation-only recipient: 43 base64url characters. */
const RECIPIENT = `tkbr1:${"B".repeat(43)}`;

beforeEach(async () => {
  await setLocale("en");
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(BackupPage, { url: "/settings/backup", path: "/settings/backup" });
  await screen.findByTestId("backup-status");
  return view;
}

function age(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

function fillPassphrase(dialog: HTMLElement, first: string, second: string) {
  fireEvent.input(within(dialog).getByTestId("field-passphrase"), { target: { value: first } });
  fireEvent.input(within(dialog).getByTestId("field-passphrase-again"), { target: { value: second } });
}

describe("the backup page", () => {
  it("shows the target, the last good backup, its age and the recent backups", async () => {
    await openPage();
    expect(screen.getByTestId("backup-target").textContent).toBe("/var/lib/tenko/backups");
    expect(screen.getByTestId("backup-last-good").textContent).toContain("3 days ago");
    expect(screen.getByTestId("backup-age").textContent).toContain("3");
    expect(screen.getByTestId("backup-next").textContent).toBe("Not scheduled");
    expect(screen.queryByTestId("backup-warnings")).toBeNull();
    const rows = screen.getAllByTestId("backup-run");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.getAttribute("data-outcome")).toBe("succeeded");
    expect(within(rows[0] as HTMLElement).getByTestId("backup-run-file").textContent).toMatch(/^tenko-backup-.*-n1\.tkbk$/);
    expect(rows[0]?.textContent).toContain("By hand");
    expect(rows[0]?.textContent).toContain("4.6 MiB");
  });

  it("warns when the last good backup is older than 7 days", async () => {
    backupState.runs = backupState.runs.map((r) => ({ ...r, finished_at: age(9) }));
    await openPage();
    const warning = await screen.findByTestId("backup-warning");
    expect(warning.getAttribute("data-code")).toBe("backup.stale");
    expect(warning.textContent).toContain("7 days");
  });

  it("shows a failed backup as a warning, in the facts and in the list", async () => {
    backupState.runs = [
      {
        ...backupState.runs[0]!,
        id: "0190d1c2-0000-7000-8000-0000000000f1",
        outcome: "failed",
        file: null,
        bytes: null,
        finished_at: new Date().toISOString(),
        error: { code: "backup.io", detail: "no space left on the device" },
      },
      ...backupState.runs,
    ];
    await openPage();
    expect((await screen.findByTestId("backup-warning")).getAttribute("data-code")).toBe("backup.failed");
    expect(screen.getByTestId("backup-last-failed").textContent).toContain("backup.io");
    const failed = screen.getAllByTestId("backup-run").find((row) => row.getAttribute("data-outcome") === "failed");
    expect(within(failed as HTMLElement).getByTestId("backup-run-error").textContent).toContain("no space left");
    // A failed run has no file, so no restore command.
    expect(within(failed as HTMLElement).queryByTestId("backup-restore-open")).toBeNull();
  });

  it("tells that the installation was restored from a backup", async () => {
    backupState.restored = {
      backup_created_at: age(2),
      file: "tenko-backup-20261010T020000Z-n1.tkbk",
      node: 2,
      restored_at: age(1),
      revision: 40,
      source_node: 1,
      started_at: age(1),
    };
    backupState.runs = [];
    await openPage();
    const restored = await screen.findByTestId("backup-restored");
    expect(restored.textContent).toContain("tenko-backup-20261010T020000Z-n1.tkbk");
    expect(screen.getAllByTestId("backup-warning").map((w) => w.getAttribute("data-code"))).toContain("backup.restored");
    expect(screen.getByTestId("backup-runs-empty")).toBeTruthy();
    expect(screen.getByTestId("backup-last-good").textContent).toBe("Never");
  });

  it("backs up now with a passphrase typed twice", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    // Without a recipient the passphrase is the only way.
    expect(within(dialog).getByTestId("backup-create-key").textContent).toContain("needs a passphrase");
    fillPassphrase(dialog, "short", "short");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Use at least 12 characters.")).toBeTruthy();
    fillPassphrase(dialog, "lantern-quartz-harbor", "lantern-quartz-harbour");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("The two passphrases differ.")).toBeTruthy();
    fillPassphrase(dialog, "lantern-quartz-harbor", "lantern-quartz-harbor");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-backup")).toBeNull());
    await waitFor(() => expect(screen.getAllByTestId("backup-run")).toHaveLength(2));
    expect(backupState.runs.some((r) => r.reason === "manual" && r.slots.join() === "passphrase")).toBe(true);
    expect(screen.getByTestId("backup-last-good").textContent).toContain("now");
  });

  it("backs up to the recipient without a passphrase when one is configured", async () => {
    backupState.settings.recipient = RECIPIENT;
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    expect(within(dialog).getByTestId("backup-create-key").textContent).toContain("encrypted to the recipient key");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(backupState.runs.some((r) => r.slots.join() === "recipient")).toBe(true));
  });

  it("adds a passphrase to a backup for the recipient only when it is complete", async () => {
    backupState.settings.recipient = RECIPIENT;
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    fillPassphrase(dialog, "lantern-quartz-harbor", "");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("The two passphrases differ.")).toBeTruthy();
    expect(backupState.runs).toHaveLength(1);
    fillPassphrase(dialog, "lantern-quartz-harbor", "lantern-quartz-harbor");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(backupState.runs.some((r) => r.slots.join() === "recipient,passphrase")).toBe(true));
  });

  it("asks for a fresh sign-in when the session is older than five minutes", async () => {
    const current = db.sessions.find((s) => s.id === db.currentSessionId)!;
    current.created_at = Date.now() - 10 * 60 * 1000;
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    fillPassphrase(dialog, "lantern-quartz-harbor", "lantern-quartz-harbor");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await screen.findByTestId("backup-step-up")).toBeTruthy();
    expect(screen.queryByTestId("dialog-backup")).toBeNull();
    expect(backupState.runs).toHaveLength(1);
  });

  it("asks for a fresh sign-in when saving the schedule with an old session", async () => {
    const current = db.sessions.find((s) => s.id === db.currentSessionId)!;
    current.created_at = Date.now() - 10 * 60 * 1000;
    await openPage();
    const form = await screen.findByTestId("backup-schedule");
    fireEvent.input(await within(form).findByTestId("field-keep"), { target: { value: "10" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByTestId("backup-step-up")).toBeTruthy();
    expect(backupState.settings.keep).toBe(7);
  });

  it("disables the button while a backup runs", async () => {
    backupState.running = true;
    await openPage();
    expect((screen.getByTestId("backup-now") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("backup-running").textContent).toBe("Yes");
  });

  it("saves an interval schedule with a recipient", async () => {
    await openPage();
    const form = await screen.findByTestId("backup-schedule");
    fireEvent.click(await within(form).findByTestId("field-enabled"));
    // Enabling without a recipient is hinted, and nothing is sent.
    expect(within(form).getByTestId("backup-needs-recipient")).toBeTruthy();
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(backupState.settings.enabled).toBe(false);
    fireEvent.input(within(form).getByTestId("field-recipient"), { target: { value: RECIPIENT } });
    expect(within(form).queryByTestId("backup-needs-recipient")).toBeNull();
    fireEvent.input(within(form).getByTestId("field-interval"), { target: { value: "12" } });
    fireEvent.input(within(form).getByTestId("field-keep"), { target: { value: "14" } });
    fireEvent.input(within(form).getByTestId("field-target-dir"), { target: { value: "/srv/backups" } });
    fireEvent.click(within(form).getByTestId("field-include-config"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(backupState.settings.enabled).toBe(true));
    expect(backupState.settings).toMatchObject({
      interval_hours: 12,
      keep: 14,
      recipient: RECIPIENT,
      target_dir: "/srv/backups",
      effective_target_dir: "/srv/backups",
      include_config: false,
    });
    expect(await screen.findByText(/Backup schedule saved: Every 12/)).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("backup-target").textContent).toBe("/srv/backups"));
    expect(screen.getByTestId("backup-next").textContent).not.toBe("Not scheduled");
  });

  it("checks the fields before it sends them", async () => {
    await openPage();
    const form = await screen.findByTestId("backup-schedule");
    fireEvent.input(await within(form).findByTestId("field-interval"), { target: { value: "200" } });
    fireEvent.input(within(form).getByTestId("field-keep"), { target: { value: "0" } });
    fireEvent.input(within(form).getByTestId("field-recipient"), { target: { value: "tkbr1:nope" } });
    fireEvent.input(within(form).getByTestId("field-target-dir"), { target: { value: "relative/dir" } });
    expect(within(form).getAllByText(/Enter a whole number from/)).toHaveLength(2);
    expect(within(form).getByText("A recipient is tkbr1: followed by 43 characters.")).toBeTruthy();
    expect(within(form).getByText(/Enter an absolute directory/)).toBeTruthy();
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(backupState.settings.keep).toBe(7);
  });

  it("shows the refusal when the settings changed since they were read", async () => {
    await openPage();
    const form = await screen.findByTestId("backup-schedule");
    fireEvent.input(await within(form).findByTestId("field-keep"), { target: { value: "9" } });
    backupState.settings = { ...backupState.settings, revision: (backupState.settings.revision ?? 0) + 1000 };
    fireEvent.click(within(form).getByTestId("form-submit"));
    const notice = await within(form).findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("sys.store.precondition_failed");
    expect(backupState.settings.keep).toBe(7);
  });

  it("shows the command that restores a backup on a new host", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("backup-restore-open"));
    const dialog = await screen.findByTestId("dialog-backup-restore");
    expect(within(dialog).getByTestId("backup-restore-command").textContent).toMatch(
      /^tenko backup restore \/var\/lib\/tenko\/backups\/tenko-backup-.*-n1\.tkbk --config <tenko\.toml of the new host>$/,
    );
    expect(dialog.textContent).toContain("a passphrase");
  });

  it("has no accessibility violations on the page and in its dialogs", async () => {
    const view = await openPage();
    await within(screen.getByTestId("backup-schedule")).findByTestId("field-enabled");
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("backup-restore-open"));
    await screen.findByTestId("dialog-backup-restore");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    fireEvent.click(screen.getByTestId("form-cancel"));
    fireEvent.click(screen.getByTestId("backup-now"));
    await screen.findByTestId("dialog-backup");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("renders in Swedish", async () => {
    await setLocale("sv");
    await openPage();
    expect(screen.getByTestId("backup-now").textContent).toContain("Säkerhetskopiera nu");
    expect(screen.getByTestId("backup-run-outcome").textContent).toBe("Lyckades");
  });
});

describe("the backup routes of the mock", () => {
  it("refuses what the server refuses, with the codes of docs/backup.md", async () => {
    const update = {
      enabled: false,
      include_config: true,
      interval_hours: 24,
      keep: 7,
      recipient: null,
      target_dir: null,
    };
    const put = (body: object, ifMatch?: number) => api.put("/api/v1/system/backups/settings", { body: { ...update, ...body }, ifMatch });
    await expect(put({ enabled: true })).rejects.toMatchObject({ code: "backup.key.missing", status: 422 });
    await expect(put({ interval_hours: 169 })).rejects.toMatchObject({ code: "backup.settings.invalid", status: 422 });
    await expect(put({ keep: 366 })).rejects.toMatchObject({ code: "backup.settings.invalid" });
    await expect(put({ target_dir: "relative" })).rejects.toMatchObject({ code: "backup.settings.invalid" });
    await expect(put({ recipient: "tkbr1:nope" })).rejects.toMatchObject({ code: "backup.key.invalid" });
    await expect(put({}, 1)).rejects.toMatchObject({ code: "sys.store.precondition_failed", status: 409 });
    const saved = await put({ enabled: true, recipient: RECIPIENT });
    expect(saved.enabled).toBe(true);
    await expect(api.post("/api/v1/system/backups", { body: { passphrase: "eleven char" } })).rejects.toMatchObject({
      code: "backup.passphrase.weak",
      status: 422,
    });
    backupState.settings.recipient = null;
    await expect(api.post("/api/v1/system/backups", { body: {} })).rejects.toMatchObject({ code: "backup.key.missing" });
    backupState.running = true;
    await expect(api.post("/api/v1/system/backups", { body: { passphrase: "twelve chars" } })).rejects.toMatchObject({
      code: "backup.running",
      status: 409,
    });
  });
});

describe("the backup model", () => {
  it("checks recipients, directories and the fields of the schedule", () => {
    expect(validRecipient(RECIPIENT)).toBe(true);
    expect(validRecipient("tkbr1:short")).toBe(false);
    expect(absoluteDir("/srv/backups")).toBe(true);
    expect(absoluteDir("C:\\Tenko\\backups")).toBe(true);
    expect(absoluteDir("backups")).toBe(false);
    const draft = draftOf(backupState.settings);
    expect(draftErrors(draft)).toEqual({});
    expect(Object.keys(draftErrors({ ...draft, intervalHours: 0, keep: 1.5 })).sort()).toEqual(["interval", "keep"]);
    expect(needsRecipient({ enabled: true, recipient: " " })).toBe(true);
    expect(needsRecipient({ enabled: false, recipient: "" })).toBe(false);
    expect(settingsBody(draft)).toEqual({
      enabled: false,
      include_config: true,
      interval_hours: 24,
      keep: 7,
      recipient: null,
      target_dir: null,
    });
    expect(settingsBody({ ...draft, recipient: ` ${RECIPIENT} `, targetDir: "/srv" })).toMatchObject({ recipient: RECIPIENT, target_dir: "/srv" });
  });

  it("words sizes, ages, intervals and schedules", () => {
    expect(sizeText(512)).toBe("512 B");
    expect(sizeText(4_812_345)).toBe("4.6 MiB");
    expect(ageText(30)).toContain("30");
    expect(ageText(2 * 86_400 + 5)).toContain("2");
    expect(intervalText(48)).toBe(intervalText(48));
    expect(intervalText(48)).not.toBe(intervalText(47));
    expect(scheduleText({ enabled: false, interval_hours: 24 })).toBe("Off");
    expect(scheduleText({ enabled: true, interval_hours: 6 })).toMatch(/^Every 6/);
  });

  it("builds the restore command from the directory and the file", () => {
    expect(restoreCommand({ file: "b.tkbk", target_dir: "/srv/backups/" })).toBe("tenko backup restore /srv/backups/b.tkbk --config <tenko.toml of the new host>");
    expect(restoreCommand({ file: "b.tkbk", target_dir: "C:\\Tenko\\backups\\" })).toBe(
      "tenko backup restore C:\\Tenko\\backups\\b.tkbk --config <tenko.toml of the new host>",
    );
  });
});
