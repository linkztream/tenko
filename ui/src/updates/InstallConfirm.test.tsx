// The backup before an update (ADR 0023): the confirmation of an install or an upload says
// how old the newest backup is and installs at once when it is recent; otherwise it asks
// whether to take one first ("Backup now" is the default), with the passphrase when no
// recipient is set up, and shows a failed backup without starting the install.
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../api/mock/db";
import { backupState } from "../api/mock/routes-backup";
import { mockReleaseFile, mockUpdates, updateStatus } from "../api/mock/routes-updates";
import { DAY_MS, iso } from "../api/mock/util";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import type { UpdateStatus } from "./api";
import { backupAgeNow, backupIsRecent, InstallConfirm } from "./InstallConfirm";
import { pageActions } from "./restart";
import { signInAdmin } from "./testkit";
import UpdatesPage from "./UpdatesPage";

/** A documentation-only recipient: 43 base64url characters. */
const RECIPIENT = `tkbr1:${"B".repeat(43)}`;
const PASSPHRASE = "lantern-quartz-harbor";
const NO_SHELL = { disable: ["region"] } as const;

afterEach(async () => {
  vi.useRealTimers();
  setSessionForTest(null);
  await setLocale("en");
});

beforeEach(() => {
  vi.spyOn(pageActions, "reload").mockImplementation(() => undefined);
});

async function openPage() {
  const view = renderRoute(UpdatesPage, { url: "/updates", path: "/updates" });
  await screen.findByTestId("updates-running");
  return view;
}

/** The newest good backup finished `ms` ago. */
function backedUp(ms: number) {
  backupState.runs = backupState.runs.map((r) => ({ ...r, finished_at: iso(Date.now() - ms) }));
}

/** The age next to the install button (the upload panel shows one too). */
const installAge = () => within(screen.getByTestId("updates-install-panel")).getByTestId("updates-backup-age");

async function openDialog(): Promise<HTMLElement> {
  fireEvent.click(screen.getByTestId("updates-install"));
  return screen.findByTestId("dialog-update-install");
}

function fillPassphrase(dialog: HTMLElement, first: string, second: string) {
  fireEvent.input(within(dialog).getByTestId("update-backup-passphrase"), { target: { value: first } });
  fireEvent.input(within(dialog).getByTestId("update-backup-passphrase-again"), { target: { value: second } });
}

const beforeUpdateRuns = () => backupState.runs.filter((r) => r.reason === "before_update");

describe("the backup age next to the install button", () => {
  it("shows how old the newest backup is, with a link to the backups", async () => {
    await signInAdmin();
    await openPage();
    const age = installAge();
    expect(age.textContent).toMatch(/^Last backup 3 days? ago\./);
    const link = within(age).getByTestId("updates-backup-link");
    expect(link.getAttribute("href")).toBe("/settings/backup");
    expect(link.textContent).toBe("Backups");
  });

  it("says when there is no backup yet", async () => {
    await signInAdmin();
    backupState.runs = [];
    await openPage();
    const age = installAge();
    expect(age.textContent).toContain("No backup yet.");
    expect(within(age).getByTestId("updates-backup-link").getAttribute("href")).toBe("/settings/backup");
  });

  it("is shown next to the upload button as well", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    backedUp(5 * 3_600_000);
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    expect(within(panel).getByTestId("updates-backup-age").textContent).toMatch(/^Last backup 5 hr ago\./);
    expect(within(panel).getByTestId("updates-backup-link").getAttribute("href")).toBe("/settings/backup");
  });
});

describe("a recent backup", () => {
  it("says how old it is and installs without the question", async () => {
    await signInAdmin();
    backedUp(12 * 60_000);
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-recent").textContent).toBe("Backed up 12 min ago.");
    expect(within(dialog).queryByTestId("update-backup-question")).toBeNull();
    expect(within(dialog).queryByTestId("update-backup-now")).toBeNull();
    expect(within(dialog).queryByTestId("update-backup-skip")).toBeNull();

    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
    expect(mockUpdates.lastBackupPlan).toBe("recent");
    expect(backupState.runs).toHaveLength(1);
  });
});

describe("the question", () => {
  it("asks, says how old the newest backup is and has \"Backup now\" focused", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-question").textContent).toBe("Are you sure you do not want a backup first?");
    expect(within(dialog).getByTestId("update-backup-age").textContent).toMatch(/^The newest backup is 3 days? old\. /);
    expect(within(dialog).queryByTestId("update-backup-recent")).toBeNull();
    expect(within(dialog).queryByTestId("confirm-ok")).toBeNull();
    expect(within(dialog).queryByTestId("update-backup-required")).toBeNull();
    const now = within(dialog).getByTestId("update-backup-now") as HTMLButtonElement;
    expect(now.textContent).toBe("Backup now");
    expect(now.type).toBe("submit");
    expect(now.classList.contains("primary")).toBe(true);
    await waitFor(() => expect(document.activeElement).toBe(now));
    expect(within(dialog).getByTestId("update-backup-skip").textContent).toBe("No, don't back up");
    expect(within(dialog).getByTestId("confirm-cancel")).toBeTruthy();
    // The action of the release is still repeated in the question.
    expect(within(dialog).getByTestId("update-confirm-action").textContent).toContain("Make a backup");
  });

  it("says that there is no backup yet", async () => {
    await signInAdmin();
    backupState.runs = [];
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-age").textContent).toMatch(/^There is no backup yet\. /);
  });

  it("changes nothing on cancel", async () => {
    await signInAdmin();
    await openPage();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-update-install")).toBeNull());
    expect(mockUpdates.attempt).toBeNull();
    expect(mockUpdates.lastBackupPlan).toBeNull();
    expect(backupState.runs).toHaveLength(1);
  });

  it("installs with a skip and takes no backup on \"No, don't back up\"", async () => {
    await signInAdmin();
    await openPage();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("update-backup-skip"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.lastBackupPlan).toBe("skipped");
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
    expect(backupState.runs).toHaveLength(1);
    expect(beforeUpdateRuns()).toHaveLength(0);
  });

  it("has no accessibility violations", async () => {
    await signInAdmin();
    await openPage();
    await openDialog();
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});

describe("\"Backup now\" with a recipient", () => {
  it("shows that it is working, records a backup before the update and then starts the install", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).queryByTestId("update-backup-passphrase")).toBeNull();

    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    const running = within(dialog).getByTestId("update-backup-running");
    expect(running.getAttribute("role")).toBe("status");
    expect(running.textContent).toContain("Backing up");
    for (const id of ["update-backup-now", "update-backup-skip", "confirm-cancel"]) {
      expect((within(dialog).getByTestId(id) as HTMLButtonElement).disabled).toBe(true);
    }

    await screen.findByTestId("updates-progress");
    expect(beforeUpdateRuns()).toHaveLength(1);
    expect(beforeUpdateRuns()[0]).toMatchObject({ before_update: "0.2.0", outcome: "succeeded", slots: ["recipient"] });
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
    // The install itself carries no answer: the backup it asked for is recent now.
    expect(mockUpdates.lastBackupPlan).toBe("recent");
    expect(screen.queryByTestId("dialog-update-install")).toBeNull();
  });
});

describe("\"Backup now\" without a recipient", () => {
  it("asks for a passphrase typed twice and refuses a short or a mismatching one without sending anything", async () => {
    await signInAdmin();
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-passphrase-lead").textContent).toContain("No backup recipient is set up");
    expect((within(dialog).getByTestId("update-backup-passphrase") as HTMLInputElement).type).toBe("password");
    expect((within(dialog).getByTestId("update-backup-passphrase-again") as HTMLInputElement).type).toBe("password");

    // Nothing is said before the first try.
    expect(dialog.querySelector(".field-error")).toBeNull();

    fillPassphrase(dialog, "short", "short");
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    expect(await within(dialog).findByText("Use at least 12 characters.")).toBeTruthy();
    expect(within(dialog).queryByTestId("update-backup-running")).toBeNull();

    fillPassphrase(dialog, PASSPHRASE, `${PASSPHRASE}x`);
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    expect(await within(dialog).findByText("The two passphrases differ.")).toBeTruthy();

    expect(backupState.runs).toHaveLength(1);
    expect(mockUpdates.attempt).toBeNull();
    expect(mockUpdates.lastBackupPlan).toBeNull();
  });

  it("backs up with the passphrase when it is valid, and then installs", async () => {
    await signInAdmin();
    await openPage();
    const dialog = await openDialog();
    fillPassphrase(dialog, PASSPHRASE, PASSPHRASE);
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    await screen.findByTestId("updates-progress");
    expect(beforeUpdateRuns()).toHaveLength(1);
    expect(beforeUpdateRuns()[0]).toMatchObject({ before_update: "0.2.0", outcome: "succeeded", slots: ["passphrase"] });
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
  });
});

describe("a backup that fails", () => {
  it("shows the problem, starts no install, offers the choices again and succeeds on the next try", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    backupState.failNext = "backup.io";
    await openPage();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));

    const failed = await within(dialog).findByTestId("update-backup-failed");
    expect(failed.textContent).toContain("The backup failed, so the update did not start.");
    expect(within(failed).getByTestId("error-notice").getAttribute("data-code")).toBe("backup.io");
    expect(failed.textContent).toContain("the target directory is full");
    expect(within(dialog).queryByTestId("update-backup-running")).toBeNull();
    expect(mockUpdates.attempt).toBeNull();
    expect(screen.queryByTestId("updates-progress")).toBeNull();
    expect(backupState.runs.some((r) => r.outcome === "failed" && r.reason === "before_update")).toBe(true);

    // Both choices are offered again.
    for (const id of ["update-backup-now", "update-backup-skip", "confirm-cancel"]) {
      expect((within(dialog).getByTestId(id) as HTMLButtonElement).disabled).toBe(false);
    }

    backupState.failNext = null;
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
    expect(backupState.runs.some((r) => r.outcome === "succeeded" && r.reason === "before_update")).toBe(true);
  });

  it("lets the administrator skip the backup after a failure", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    backupState.failNext = "backup.io";
    await openPage();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    await within(dialog).findByTestId("update-backup-failed");
    fireEvent.click(within(dialog).getByTestId("update-backup-skip"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.lastBackupPlan).toBe("skipped");
  });
});

describe("the Hardened profile", () => {
  it("requires a backup: no skip, and the reason is said", async () => {
    await signInAdmin();
    db.settings.profile = "hardened";
    // The profile also limits installs to a file; the server fetches again in this arrangement.
    db.settings.updates = { check: true, install: "ui" };
    backupState.settings.recipient = RECIPIENT;
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).queryByTestId("update-backup-skip")).toBeNull();
    expect(within(dialog).getByTestId("update-backup-required").textContent).toBe("This security profile requires a backup before every update.");
    expect(within(dialog).getByTestId("update-backup-now")).toBeTruthy();

    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    await screen.findByTestId("updates-progress");
    expect(beforeUpdateRuns()).toHaveLength(1);
  });

  it("does not show the requirement where a skip is allowed", async () => {
    await signInAdmin();
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).queryByTestId("update-backup-required")).toBeNull();
  });
});

describe("a step-up answer to the backup", () => {
  it("shows the fresh sign-in explanation and starts nothing", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    // A backup needs a sign-in within the last five minutes.
    const current = db.sessions.find((s) => s.id === db.currentSessionId)!;
    current.created_at = Date.now() - 10 * 60 * 1000;
    await openPage();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));

    const notice = await screen.findByTestId("updates-stepup");
    expect(notice.textContent).toContain("Sign in again to continue");
    expect(screen.queryByTestId("dialog-update-install")).toBeNull();
    expect(screen.queryByTestId("updates-progress")).toBeNull();
    expect(mockUpdates.attempt).toBeNull();
    expect(backupState.runs).toHaveLength(1);
  });
});

describe("the answer of the server about the backup", () => {
  it("shows the error and reads the status again when the backup is no longer recent", async () => {
    await signInAdmin();
    backedUp(12 * 60_000);
    await openPage();
    expect(installAge().textContent).toContain("12 min");
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-recent")).toBeTruthy();

    // The backup ages past the limit while the dialog is open.
    backedUp(2 * DAY_MS);
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("A backup is needed before this update.");
    expect(alert.getAttribute("data-code")).toBe("update.backup_required");
    expect(mockUpdates.attempt).toBeNull();
    expect(screen.queryByTestId("updates-progress")).toBeNull();
    await waitFor(() => expect(installAge().textContent).toMatch(/Last backup 2 days? ago\./));

    // The next try asks the question.
    const again = await openDialog();
    expect(within(again).getByTestId("update-backup-question")).toBeTruthy();
  });
});

describe("an upload", () => {
  async function chooseFile() {
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    fireEvent.change(within(panel).getByTestId("updates-release-file"), {
      target: { files: [new File([mockReleaseFile("0.2.0")], "tenko-0.2.0-linux-x86_64")] },
    });
    fireEvent.click(within(panel).getByTestId("updates-upload"));
    return screen.findByTestId("dialog-update-install");
  }

  it("asks the question as well, and uploads with a skip", async () => {
    await signInAdmin();
    const dialog = await chooseFile();
    expect(within(dialog).getByTestId("update-backup-question")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("update-backup-skip"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.lastBackupPlan).toBe("skipped");
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
  });

  it("backs up first and then uploads", async () => {
    await signInAdmin();
    backupState.settings.recipient = RECIPIENT;
    const dialog = await chooseFile();
    fireEvent.click(within(dialog).getByTestId("update-backup-now"));
    await screen.findByTestId("updates-progress");
    expect(beforeUpdateRuns()).toHaveLength(1);
    expect(beforeUpdateRuns()[0]?.before_update).toBe("0.2.0");
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
  });

  it("uploads at once when the backup is recent", async () => {
    await signInAdmin();
    backedUp(30 * 60_000);
    const dialog = await chooseFile();
    expect(within(dialog).getByTestId("update-backup-recent").textContent).toBe("Backed up 30 min ago.");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.lastBackupPlan).toBe("recent");
  });
});

describe("the one-hour rule on the client", () => {
  function craft(backup: { age_seconds?: number | null; skip_allowed?: boolean; recipient?: boolean }): UpdateStatus {
    const status = updateStatus();
    const { age_seconds: age, ...rest } = backup;
    return {
      ...status,
      install: {
        ...status.install,
        backup: {
          max_age_seconds: 3600,
          skip_allowed: true,
          recipient: true,
          ...rest,
          ...(age === undefined || age === null ? {} : { age_seconds: age }),
        },
      },
    };
  }

  function renderConfirm(status: UpdateStatus, receivedAt: number) {
    const handlers = { onConfirm: vi.fn(), onFailure: vi.fn(), onClose: vi.fn() };
    render(() => <InstallConfirm status={status} version="0.2.0" kind="download" busy={false} receivedAt={receivedAt} {...handlers} />);
    return handlers;
  }

  beforeEach(async () => {
    await signInAdmin();
  });

  it("asks the question for a backup that was recent when the status arrived but is not any more", () => {
    // 3500 s old when the status arrived 200 s ago: 3700 s now.
    renderConfirm(craft({ age_seconds: 3500 }), Date.now() - 200_000);
    expect(screen.getByTestId("update-backup-question")).toBeTruthy();
    expect(screen.queryByTestId("update-backup-recent")).toBeNull();
    expect(screen.getByTestId("update-backup-age").textContent).toMatch(/^The newest backup is 1 hr old\./);
  });

  it("does not ask for a backup that is still recent when the status arrived a little ago", () => {
    renderConfirm(craft({ age_seconds: 3500 }), Date.now() - 50_000);
    expect(screen.getByTestId("update-backup-recent").textContent).toBe("Backed up 59 min ago.");
    expect(screen.queryByTestId("update-backup-question")).toBeNull();
  });

  it("answers nothing when the backup is recent", () => {
    const recent = renderConfirm(craft({ age_seconds: 60 }), Date.now());
    fireEvent.click(screen.getByTestId("confirm-ok"));
    expect(recent.onConfirm).toHaveBeenCalledExactlyOnceWith(undefined);
  });

  it("answers \"skip\" when the administrator declines", () => {
    const asked = renderConfirm(craft({ age_seconds: 7200 }), Date.now());
    fireEvent.click(screen.getByTestId("update-backup-skip"));
    expect(asked.onConfirm).toHaveBeenCalledExactlyOnceWith("skip");
  });

  it("hands a step-up answer of the backup to the panel and installs nothing", async () => {
    const current = db.sessions.find((s) => s.id === db.currentSessionId)!;
    current.created_at = Date.now() - 10 * 60 * 1000;
    const asked = renderConfirm(craft({ age_seconds: 7200 }), Date.now());
    fireEvent.click(screen.getByTestId("update-backup-now"));
    await waitFor(() => expect(asked.onFailure).toHaveBeenCalledTimes(1));
    expect(asked.onFailure.mock.calls[0]?.[0]).toMatchObject({ code: "auth.step_up_required" });
    expect(asked.onConfirm).not.toHaveBeenCalled();
  });

  it("closes on cancel", () => {
    const asked = renderConfirm(craft({}), Date.now());
    expect(screen.getByTestId("update-backup-age").textContent).toMatch(/^There is no backup yet\./);
    fireEvent.click(screen.getByTestId("confirm-cancel"));
    expect(asked.onClose).toHaveBeenCalledTimes(1);
  });

  describe("the pure functions", () => {
    const at = 1_000_000_000_000;

    it("age the status by the time since it arrived", () => {
      const status = craft({ age_seconds: 100 });
      expect(backupAgeNow(status, at, at)).toBe(100);
      expect(backupAgeNow(status, at, at + 59_999)).toBe(159);
      expect(backupAgeNow(status, at, at + 200_000)).toBe(300);
      // A clock that went back does not make the backup younger.
      expect(backupAgeNow(status, at, at - 5_000)).toBe(100);
    });

    it("have no age without a backup, and a missing age is no recent backup", () => {
      const none = craft({});
      expect(backupAgeNow(none, at, at)).toBeNull();
      expect(backupIsRecent(none, at, at)).toBe(false);
      const missing = craft({ age_seconds: null });
      expect(backupAgeNow(missing, at, at + 10_000)).toBeNull();
      expect(backupIsRecent(missing, at, at + 10_000)).toBe(false);
    });

    it("call a backup recent only when it is younger than the limit", () => {
      const status = craft({ age_seconds: 3599 });
      expect(backupIsRecent(status, at, at)).toBe(true);
      // Exactly the limit is not recent.
      expect(backupIsRecent(craft({ age_seconds: 3600 }), at, at)).toBe(false);
      expect(backupIsRecent(status, at, at + 1_000)).toBe(false);
      expect(backupIsRecent(craft({ age_seconds: 0 }), at, at)).toBe(true);
    });

    it("use the limit the server reports", () => {
      const status = craft({ age_seconds: 100 });
      const strict = { ...status, install: { ...status.install, backup: { ...status.install.backup, max_age_seconds: 60 } } };
      expect(backupIsRecent(strict, at, at)).toBe(false);
      expect(backupIsRecent(status, at, at)).toBe(true);
    });
  });
});

describe("in Swedish", () => {
  it("renders the age, the question and the buttons without a message key", async () => {
    await signInAdmin();
    await setLocale("sv");
    await openPage();
    expect(installAge().textContent).toContain("Senaste säkerhetskopian för");
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-question").textContent).toBe("Är du säker på att du inte vill ta en säkerhetskopia först?");
    expect(within(dialog).getByTestId("update-backup-now").textContent).toBe("Säkerhetskopiera nu");
    expect(within(dialog).getByTestId("update-backup-skip").textContent).toBe("Nej, säkerhetskopiera inte");
    expect(within(dialog).getByTestId("update-backup-age").textContent).toContain("Den senaste säkerhetskopian är");
    // No untranslated key shows.
    expect(dialog.textContent).not.toMatch(/updates\.backup\./);
  });

  it("renders the recent backup in Swedish", async () => {
    await signInAdmin();
    backedUp(12 * 60_000);
    await setLocale("sv");
    await openPage();
    const dialog = await openDialog();
    expect(within(dialog).getByTestId("update-backup-recent").textContent).toContain("Säkerhetskopierad för");
  });
});
