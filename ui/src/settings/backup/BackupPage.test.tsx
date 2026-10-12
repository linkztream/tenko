import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { backupState } from "../../api/mock/routes-backup";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import BackupPage from "./BackupPage";
import { restoreCommand, scheduleText, sizeText, validTime } from "./model";

const NO_SHELL = { disable: ["region"] } as const;

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

describe("the backup page", () => {
  it("shows the target, the last good backup and the backups there", async () => {
    await openPage();
    expect(screen.getByTestId("backup-target").textContent).toBe("/var/lib/tenko/backups");
    expect(screen.getByTestId("backup-last-good").textContent).toContain("3 days ago");
    expect(screen.queryByTestId("backup-stale")).toBeNull();
    expect(screen.getAllByTestId("backup-file")).toHaveLength(1);
  });

  it("warns when the last good backup is older than 7 days", async () => {
    backupState.backups = backupState.backups.map((b) => ({ ...b, created_at: new Date(Date.now() - 9 * 86_400_000).toISOString() }));
    await openPage();
    expect(await screen.findByTestId("backup-stale")).toBeTruthy();
  });

  it("backs up now with a passphrase typed twice", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    // Without a recipient key file the passphrase is the only way.
    expect(within(dialog).queryByTestId("field-key-recipient")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-passphrase"), { target: { value: "short" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Use at least 12 characters.")).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-passphrase"), { target: { value: "lantern-quartz-harbor" } });
    fireEvent.input(within(dialog).getByTestId("field-passphrase-again"), { target: { value: "lantern-quartz-harbour" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("The two passphrases differ.")).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-passphrase-again"), { target: { value: "lantern-quartz-harbor" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-backup")).toBeNull());
    await waitFor(() => expect(screen.getAllByTestId("backup-file")).toHaveLength(2));
    expect(screen.getByTestId("backup-job")).toBeTruthy();
    expect(backupState.backups.some((b) => b.key === "passphrase" && b.trigger === "manual")).toBe(true);
  });

  it("backs up with the recipient key file when one is configured", async () => {
    backupState.recipient = true;
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    expect((within(dialog).getByTestId("field-key-recipient") as HTMLInputElement).checked).toBe(true);
    expect(within(dialog).queryByTestId("field-passphrase")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(backupState.backups.some((b) => b.key === "recipient")).toBe(true));
  });

  it("asks for a fresh sign-in when the session is older than five minutes", async () => {
    const current = db.sessions.find((s) => s.id === db.currentSessionId)!;
    current.created_at = Date.now() - 10 * 60 * 1000;
    await openPage();
    fireEvent.click(screen.getByTestId("backup-now"));
    const dialog = await screen.findByTestId("dialog-backup");
    fireEvent.input(within(dialog).getByTestId("field-passphrase"), { target: { value: "lantern-quartz-harbor" } });
    fireEvent.input(within(dialog).getByTestId("field-passphrase-again"), { target: { value: "lantern-quartz-harbor" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await screen.findByTestId("backup-step-up")).toBeTruthy();
    expect(screen.queryByTestId("dialog-backup")).toBeNull();
    expect(backupState.backups).toHaveLength(1);
  });

  it("saves a weekly schedule and says that it needs a recipient key file", async () => {
    await openPage();
    const form = await screen.findByTestId("backup-schedule");
    await within(form).findByTestId("field-schedule-off");
    fireEvent.click(within(form).getByTestId("field-schedule-weekly"));
    expect(within(form).getByTestId("backup-needs-recipient")).toBeTruthy();
    fireEvent.change(within(form).getByTestId("field-weekday"), { target: { value: "2" } });
    fireEvent.input(within(form).getByTestId("field-time"), { target: { value: "03:15" } });
    fireEvent.input(within(form).getByTestId("field-keep"), { target: { value: "14" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(backupState.settings.schedule).toEqual({ kind: "weekly", time: "03:15", weekday: 2 }));
    expect(backupState.settings.keep).toBe(14);
    expect(await screen.findByText("Backup schedule saved: Every Wednesday at 03:15")).toBeTruthy();
  });

  it("previews the restore of a backup with its manifest and command", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("backup-preview"));
    const dialog = await screen.findByTestId("dialog-backup-preview");
    expect(within(dialog).getByTestId("backup-preview-version").textContent).toBe("0.1.0");
    expect(within(dialog).getByTestId("backup-preview-parts").textContent).toContain("leases");
    expect(within(dialog).getByTestId("backup-restore-command").textContent).toMatch(
      /^tenko backup restore \/var\/lib\/tenko\/backups\/tenko-.*\.tkbk --data-dir <new data directory>$/,
    );
  });

  it("has no accessibility violations on the page and in its dialogs", async () => {
    const view = await openPage();
    await within(screen.getByTestId("backup-schedule")).findByTestId("field-schedule-off");
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("backup-preview"));
    await screen.findByTestId("dialog-backup-preview");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});

describe("the backup model", () => {
  it("checks times, sizes, schedules and the restore command", () => {
    expect(validTime("02:30")).toBe(true);
    expect(validTime("24:00")).toBe(false);
    expect(sizeText(512)).toBe("512 B");
    expect(sizeText(4_812_345)).toBe("4.6 MiB");
    expect(scheduleText({ kind: "off", time: "02:30" })).toBe("Off");
    expect(scheduleText({ kind: "daily", time: "02:30" })).toBe("Every day at 02:30");
    const file = { file: "b.tkbk" } as never;
    expect(restoreCommand(file, "C:\\Tenko\\backups\\")).toBe("tenko backup restore C:\\Tenko\\backups\\b.tkbk --data-dir <new data directory>");
  });
});
