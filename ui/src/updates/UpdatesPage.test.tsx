import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../api/mock/db";
import { backupState } from "../api/mock/routes-backup";
import { mockReleaseFile, mockUpdates } from "../api/mock/routes-updates";
import { iso } from "../api/mock/util";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { authState, setSessionForTest } from "../auth/session";
import { pageActions } from "./restart";
import { signInAdmin } from "./testkit";
import UpdatesPage from "./UpdatesPage";

afterEach(() => {
  vi.useRealTimers();
  setSessionForTest(null);
});

beforeEach(() => {
  vi.spyOn(pageActions, "reload").mockImplementation(() => undefined);
});

async function openPage() {
  const view = renderRoute(UpdatesPage, {
    url: "/updates",
    path: "/updates",
    routes: {
      "/signin": () => <div data-testid="signin-page" />,
      "/settings/security": () => <div data-testid="settings-page" />,
    },
  });
  await screen.findByTestId("updates-running");
  return view;
}

/** The newest good backup finished 12 minutes ago: an install goes ahead without the backup question. */
function backedUpRecently() {
  backupState.runs = backupState.runs.map((r) => ({ ...r, finished_at: iso(Date.now() - 12 * 60_000) }));
}

function release(version: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-testid="update-release"][data-key="${version}"]`);
  if (!el) throw new Error(`no release ${version}`);
  return el;
}

function file(content: string, name = "tenko-release"): File {
  return new File([content], name);
}

function choose(input: HTMLElement, chosen: File) {
  fireEvent.change(input, { target: { files: [chosen] } });
}

describe("the updates page", () => {
  it("shows the running version and every newer release, newest first, with its marks", async () => {
    await signInAdmin();
    await openPage();
    expect(screen.getByTestId("updates-running-version").textContent).toBe("0.1.0-dev");
    expect(screen.getByTestId("updates-newest").textContent).toBe("0.2.0");

    const versions = Array.from(document.querySelectorAll('[data-testid="update-release"]')).map((r) => r.getAttribute("data-key"));
    expect(versions).toEqual(["0.2.0", "0.1.1"]);
    expect(within(release("0.2.0")).getByText("Newest")).toBeTruthy();

    // The marks are a word and an icon, never color alone.
    const needsAction = within(release("0.2.0")).getByTestId("update-mark");
    expect(needsAction.getAttribute("data-key")).toBe("action");
    expect(needsAction.textContent).toBe("Action required");
    expect(needsAction.querySelector("svg")).not.toBeNull();
    expect(within(release("0.2.0")).queryByText("Security fixes")).toBeNull();
    const security = within(release("0.1.1")).getByTestId("update-mark");
    expect(security.getAttribute("data-key")).toBe("security");
    expect(security.textContent).toBe("Security fixes");
    expect(within(release("0.1.1")).queryByText("Action required")).toBeNull();
  });

  it("shows the action text of a release prominently, above its notes", async () => {
    await signInAdmin();
    await openPage();
    const card = release("0.2.0");
    const action = within(card).getByTestId("update-action");
    expect(action.textContent).toContain("You must do this when upgrading:");
    expect(action.textContent).toContain("Make a backup of the data directory.");
    expect(action.querySelector("code")?.textContent).toBe("tenko");
    // The action comes before the notes.
    const notes = card.querySelector(".md:not(.upd-action .md)") as HTMLElement;
    expect(action.compareDocumentPosition(notes) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(card).getByText("Added")).toBeTruthy();
  });

  it("renders the notes as safe text and opens links in a new tab without an opener", async () => {
    await signInAdmin();
    mockUpdates.releases[1] = {
      ...mockUpdates.releases[1]!,
      notes: "### Fixed\n- <script>window.hacked = true</script> [advisory](https://example.org/a) [bad](javascript:alert(1))",
    };
    await openPage();
    const card = release("0.1.1");
    expect(card.querySelector("script")).toBeNull();
    expect(card.textContent).toContain("<script>window.hacked = true</script>");
    const links = card.querySelectorAll("a:not(.upd-notes-link)");
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(links[0]?.getAttribute("target")).toBe("_blank");
    expect(card.textContent).toContain("[bad](javascript:alert(1))");
  });

  it("is accessible", async () => {
    await signInAdmin();
    await openPage();
    expect(await axeViolations(screen.getByTestId("page-updates"))).toEqual([]);
  });

  it("says when the installation is up to date", async () => {
    await signInAdmin();
    mockUpdates.running = "0.2.0";
    await openPage();
    expect(screen.getByTestId("updates-uptodate").textContent).toContain("Version 0.2.0 is the newest release");
    expect(screen.getByText("There is no newer release.")).toBeTruthy();
    expect(screen.queryByTestId("update-release")).toBeNull();
    expect(screen.queryByTestId("updates-install")).toBeNull();
  });

  it("says that the installation offers no updates when the server has no update service", async () => {
    await signInAdmin();
    mockUpdates.unavailable = true;
    renderRoute(UpdatesPage, { url: "/updates", path: "/updates" });
    expect((await screen.findByTestId("updates-unavailable")).textContent).toContain("does not offer updates");
    expect(screen.queryByTestId("updates-running")).toBeNull();
  });

  it("shows the settings navigation with the updates tab, like the other settings pages", async () => {
    await signInAdmin();
    renderRoute(UpdatesPage, { url: "/updates", path: "/updates" });
    const nav = await screen.findByTestId("settings-nav");
    const keys = within(nav).getAllByTestId("settings-nav-link").map((a) => a.dataset.key);
    expect(keys).toContain("updates");
  });
});

describe("the links to the release notes", () => {
  const BASE = "https://github.example.org/example/tenko/releases/tag";

  it("builds the address of the release page from the release source, for the running version and each release", async () => {
    await signInAdmin();
    await openPage();
    const links = screen.getAllByTestId("release-notes-link");
    expect(links.map((l) => l.getAttribute("href"))).toEqual([`${BASE}/v0.1.0-dev`, `${BASE}/v0.2.0`, `${BASE}/v0.1.1`]);
    for (const link of links) {
      expect(link.textContent).toBe("Release notes");
      expect(link.getAttribute("target")).toBe("_blank");
      expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    }
    expect(within(release("0.2.0")).getByTestId("release-notes-link").getAttribute("aria-label")).toBe(
      "Release notes for version 0.2.0 (opens in a new tab)",
    );
    expect(document.querySelector(".page-head")?.contains(links[0] ?? null)).toBe(true);
  });

  it("shows nothing for a source the address of a release page cannot be built from", async () => {
    await signInAdmin();
    mockUpdates.source = "https://releases.example.org/tenko/releases.json";
    await openPage();
    expect(screen.queryByTestId("release-notes-link")).toBeNull();
  });

  it("shows nothing while the check is off and no manifest is loaded", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    mockUpdates.manifest = null;
    mockUpdates.releases = [];
    await openPage();
    expect(screen.queryByTestId("release-notes-link")).toBeNull();
  });

  it("keeps the links of a manifest that was uploaded while the check is off", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    mockUpdates.manifest = { origin: "uploaded", at: iso(Date.now() - 3_600_000), releases: 3 };
    await openPage();
    expect(screen.getAllByTestId("release-notes-link").length).toBe(3);
  });
});

describe("the update check", () => {
  it("shows the source, the interval and when it last ran, and checks on request", async () => {
    await signInAdmin();
    mockUpdates.lastChecked = iso(Date.now() - 86_400_000 * 3);
    await openPage();
    expect(screen.getByTestId("updates-source").textContent).toBe("https://github.example.org/example/tenko/releases/latest/download/releases.json");
    expect(screen.getByTestId("updates-check-state").textContent).toBe("On, every 24 hours");
    const before = screen.getByTestId("updates-last-checked").textContent;

    fireEvent.click(screen.getByTestId("updates-check"));
    expect(await screen.findByText("A newer release is available.")).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("updates-last-checked").textContent).not.toBe(before));
    expect(mockUpdates.lastChecked).not.toBeNull();
  });

  it("translates the last error by its code, and shows a code it has no words for", async () => {
    await signInAdmin();
    mockUpdates.lastError = "update.fetch_failed";
    await openPage();
    expect(screen.getByTestId("updates-last-error").textContent).toBe("The release source did not answer with a valid release list.");
  });

  it("shows an unknown error code as it is", async () => {
    await signInAdmin();
    mockUpdates.lastError = "update.something_new";
    await openPage();
    expect(screen.getByTestId("updates-last-error").textContent).toBe("Error code update.something_new");
  });

  it("shows the message of a failed check", async () => {
    await signInAdmin();
    mockUpdates.fetchFails = true;
    await openPage();
    fireEvent.click(screen.getByTestId("updates-check"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("The release source did not answer with a valid release list.");
    await waitFor(() => expect(screen.getByTestId("updates-last-error").textContent).toContain("did not answer"));
  });

  it("says why the check is off: air-gapped installation", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    await openPage();
    expect(screen.getByTestId("updates-check-state").textContent).toBe("Off: this installation is air-gapped.");
    expect((screen.getByTestId("updates-check") as HTMLButtonElement).disabled).toBe(true);
  });

  it("says why the check is off: the security setting, with a way to change it", async () => {
    await signInAdmin();
    db.settings.updates = { check: false, install: "ui" };
    await openPage();
    expect(screen.getByTestId("updates-check-state").textContent).toBe("Off: switched off in the security settings.");
    expect((screen.getByTestId("updates-check") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("link", { name: "Open the security settings" }).getAttribute("href")).toBe("/settings/security");
  });

  it("names where the release list came from", async () => {
    await signInAdmin();
    await openPage();
    expect(screen.getByTestId("updates-manifest-info").getAttribute("data-key")).toBe("fetched");
    expect(screen.getByTestId("updates-manifest-info").textContent).toContain("lists 3 releases");
  });
});

describe("installing from the release source", () => {
  it("asks for a confirmation that names the version and repeats the action of the release", async () => {
    await signInAdmin();
    backedUpRecently();
    await openPage();
    fireEvent.click(screen.getByTestId("updates-install"));
    const dialog = await screen.findByTestId("dialog-update-install");
    expect(within(dialog).getByText("Install version 0.2.0?")).toBeTruthy();
    expect(dialog.textContent).toContain("If the new version is not ready within 120 seconds");
    expect(dialog.textContent).toContain("This upgrade includes security fixes.");
    const action = within(dialog).getByTestId("update-confirm-action");
    expect(action.textContent).toContain("This upgrade needs an action from you:");
    expect(action.textContent).toContain("Make a backup of the data directory.");
    expect(within(dialog).getByTestId("confirm-ok").textContent).toBe("Install 0.2.0");
    expect(within(dialog).getByTestId("update-backup-recent").textContent).toBe("Backed up 12 min ago.");
    expect(within(dialog).queryByTestId("update-backup-question")).toBeNull();

    // Cancel changes nothing.
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-update-install")).toBeNull());
    expect(mockUpdates.attempt).toBeNull();
  });

  it("does not repeat an action when no release on the way asks for one", async () => {
    await signInAdmin();
    mockUpdates.releases = mockUpdates.releases.filter((r) => r.version !== "0.2.0");
    await openPage();
    expect(screen.getByTestId("updates-install").textContent).toContain("Install 0.1.1");
    fireEvent.click(screen.getByTestId("updates-install"));
    const dialog = await screen.findByTestId("dialog-update-install");
    expect(within(dialog).queryByTestId("update-confirm-action")).toBeNull();
  });

  it("follows the job, then waits for the new version to answer and reloads the page", async () => {
    await signInAdmin();
    backedUpRecently();
    await openPage();
    fireEvent.click(screen.getByTestId("updates-install"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));

    const progress = await screen.findByTestId("updates-progress");
    // The four steps of the install job, in words.
    await waitFor(() => expect(within(progress).getAllByTestId("updates-step")).toHaveLength(4));
    const steps = within(progress).getAllByTestId("updates-step");
    expect(steps.map((s) => s.getAttribute("data-key"))).toEqual(["sys.update.fetch", "sys.update.verify", "sys.update.check", "sys.update.switch"]);
    expect(steps[0]?.textContent).toContain("Download the release file");
    expect(within(progress).getByTestId("updates-job-link").getAttribute("href")).toMatch(/^\/jobs\//);

    // The job is done: the server restarts into the new version.
    await waitFor(() => expect(progress.getAttribute("data-state")).toBe("restarting"));
    expect(within(progress).getByText("Restarting into 0.2.0…")).toBeTruthy();
    expect(screen.queryByTestId("updates-install")).toBeNull();
    expect(pageActions.reload).not.toHaveBeenCalled();
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
  });

  /** Clicks Install and confirms, with fake timers on from the click, until the restart is awaited. */
  async function installUnderFakeTimers() {
    await openPage();
    vi.useFakeTimers();
    fireEvent.click(screen.getByTestId("updates-install"));
    fireEvent.click(within(await vi.waitFor(() => screen.getByTestId("dialog-update-install"))).getByTestId("confirm-ok"));
    return vi.waitFor(() => {
      const progress = screen.getByTestId("updates-progress");
      expect(progress.getAttribute("data-state")).toBe("restarting");
      return progress;
    });
  }

  it("polls the health probe every two seconds and reloads when it names the new version", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.restartMs = 5000;
    const progress = await installUnderFakeTimers();

    // The server is down for the first probes (it answers 503 while it restarts).
    await vi.advanceTimersByTimeAsync(3000);
    expect(pageActions.reload).not.toHaveBeenCalled();
    expect(progress.getAttribute("data-state")).toBe("restarting");

    // The new version answers: the page reloads.
    await vi.advanceTimersByTimeAsync(4000);
    expect(pageActions.reload).toHaveBeenCalledTimes(1);
    expect(mockUpdates.running).toBe("0.2.0");
    // It stops asking.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(pageActions.reload).toHaveBeenCalledTimes(1);
  });

  it("keeps asking while the old version answers", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.restartMs = 100;
    mockUpdates.rollBackNext = true;
    await installUnderFakeTimers();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(pageActions.reload).not.toHaveBeenCalled();
  });

  it("gives up after the ready time plus a minute, and shows that the old version runs again (rolled back)", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.rollBackNext = true;
    const progress = await installUnderFakeTimers();

    // 120 s of ready time and 60 s more.
    await vi.advanceTimersByTimeAsync(170_000);
    expect(progress.getAttribute("data-state")).toBe("restarting");
    await vi.advanceTimersByTimeAsync(14_000);

    await vi.waitFor(() => expect(progress.getAttribute("data-state")).toBe("rolled_back"));
    const outcome = within(progress).getByTestId("updates-outcome");
    expect(outcome.textContent).toContain("Version 0.2.0 did not become ready. Version 0.1.0-dev is running again.");
    expect(outcome.textContent).toContain("Reason: The new version did not become ready in time.");
    expect(pageActions.reload).not.toHaveBeenCalled();
  });

  it("says what to check when the server does not come back and the attempt says nothing", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.restartMs = 10_000_000;
    const progress = await installUnderFakeTimers();
    // The attempt stays "restarting" in the mock: the server never answered.
    await vi.advanceTimersByTimeAsync(184_000);
    await vi.waitFor(() => expect(progress.getAttribute("data-state")).toBe("timeout"));
    const notice = within(progress).getByTestId("updates-timeout");
    expect(notice.textContent).toContain("The server did not come back");
    expect(notice.textContent).toContain("did not answer within 180 seconds");
    expect(notice.textContent).toContain("The server log says why the new version did not start.");
  });

  it("explains a step-up answer and signs in again with the updates page as the way back", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.stepUpSession = db.currentSessionId;
    const view = await openPage();
    fireEvent.click(screen.getByTestId("updates-install"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));

    const notice = await screen.findByTestId("updates-stepup");
    expect(notice.textContent).toContain("Sign in again to continue");
    expect(notice.textContent).toContain("you return to this page");
    expect(mockUpdates.attempt).toBeNull();
    expect(screen.queryByTestId("updates-progress")).toBeNull();

    fireEvent.click(within(notice).getByTestId("updates-signin-again"));
    await waitFor(() => expect(authState()).toBe("signed-out"));
    await screen.findByTestId("signin-page");
    expect(view.location()).toBe("/signin?next=%2Fupdates");
  });

  it("tells that the install needs a fresh sign-in before it starts when the setting says so", async () => {
    await signInAdmin();
    await openPage();
    // Standard asks for a step-up before an install.
    expect(screen.getByTestId("updates-stepup-hint").textContent).toContain("fresh sign-in");
  });

  it("shows the refusal of the server when the install is blocked since the page was read", async () => {
    await signInAdmin();
    backedUpRecently();
    await openPage();
    mockUpdates.blocked = "cluster";
    fireEvent.click(screen.getByTestId("updates-install"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));
    expect((await screen.findByRole("alert")).textContent).toBe("This installation cannot install the update now.");
    // The page read the status again and now says why.
    await waitFor(() => expect(screen.getByTestId("updates-blocked-reason").getAttribute("data-key")).toBe("cluster"));
  });
});

describe("when an install is not possible from here", () => {
  const CASES: [string, () => void, string][] = [
    ["container", () => (mockUpdates.blocked = "container"), "This server runs in a container."],
    ["cluster", () => (mockUpdates.blocked = "cluster"), "This node belongs to a cluster."],
    ["layout_missing", () => (mockUpdates.blocked = "layout_missing"), "does not use the versioned directory layout"],
    ["unsupervised", () => (mockUpdates.blocked = "unsupervised"), "No service manager restarts the server after the switch."],
    ["unsupported_platform", () => (mockUpdates.blocked = "unsupported_platform"), "There is no release file for this platform (linux-x86_64)."],
    ["no_asset", () => (mockUpdates.blocked = "no_asset"), "The newest release has no file for this platform."],
    ["air_gapped", () => (mockUpdates.airGapped = true), "This installation is air-gapped and does not download releases."],
    ["upload_only", () => (db.settings.updates = { check: true, install: "upload_only" }), "allow installing only from an uploaded file"],
    [
      "in_progress",
      () => (mockUpdates.attempt = { from: "0.1.0-dev", to: "0.1.1", state: "installing", at: iso(Date.now()) }),
      "An update is already in progress.",
    ],
  ];

  for (const [reason, arrange, text] of CASES) {
    it(`says why: ${reason}`, async () => {
      await signInAdmin();
      arrange();
      await openPage();
      const why = await screen.findByTestId("updates-blocked-reason");
      expect(why.getAttribute("data-key")).toBe(reason);
      expect(why.textContent).toContain(text);
      expect(screen.queryByTestId("updates-install")).toBeNull();
    });
  }

  it("shows the pull command of a container in a code block, with a copy button", async () => {
    await signInAdmin();
    mockUpdates.blocked = "container";
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    await openPage();
    const command = await screen.findByTestId("updates-pull-command");
    expect(command.tagName).toBe("CODE");
    expect(command.closest("pre")).not.toBeNull();
    expect(command.textContent).toBe("docker pull registry.example.org/tenko:0.2.0");

    fireEvent.click(screen.getByTestId("updates-copy"));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("docker pull registry.example.org/tenko:0.2.0"));
    expect(await screen.findByText("Copied")).toBeTruthy();
  });

  it("offers a link to the security settings when only an upload is allowed", async () => {
    await signInAdmin();
    db.settings.updates = { check: true, install: "upload_only" };
    await openPage();
    expect(screen.getByRole("link", { name: "Open the security settings" })).toBeTruthy();
  });
});

describe("installing from files", () => {
  it("offers the upload when the installation is air-gapped and installs the file the server accepts", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    expect((within(panel).getByTestId("updates-upload-version") as HTMLSelectElement).value).toBe("0.2.0");
    expect(within(panel).getByTestId("updates-expected-file").textContent).toBe("Expected file: tenko-0.2.0-linux-x86_64 (19 byte)");
    const upload = within(panel).getByTestId("updates-upload") as HTMLButtonElement;
    expect(upload.disabled).toBe(true);

    choose(within(panel).getByTestId("updates-release-file"), file(mockReleaseFile("0.2.0"), "tenko-0.2.0-linux-x86_64"));
    expect(within(panel).getByTestId("updates-chosen-file").textContent).toBe("Chosen: tenko-0.2.0-linux-x86_64 (19 byte)");
    expect(upload.disabled).toBe(false);
    fireEvent.click(upload);

    const dialog = await screen.findByTestId("dialog-update-install");
    expect(within(dialog).getByText("Install version 0.2.0?")).toBeTruthy();
    expect(within(dialog).getByTestId("update-confirm-action").textContent).toContain("Make a backup");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    const progress = await screen.findByTestId("updates-progress");
    await waitFor(() => expect(progress.getAttribute("data-state")).toBe("restarting"));
    expect(mockUpdates.attempt?.to).toBe("0.2.0");
  });

  it("uploads the version that is chosen", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    fireEvent.change(within(panel).getByTestId("updates-upload-version"), { target: { value: "0.1.1" } });
    expect(within(panel).getByTestId("updates-expected-file").textContent).toContain("tenko-0.1.1-linux-x86_64");
    choose(within(panel).getByTestId("updates-release-file"), file(mockReleaseFile("0.1.1")));
    fireEvent.click(within(panel).getByTestId("updates-upload"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));
    await screen.findByTestId("updates-progress");
    expect(mockUpdates.attempt?.to).toBe("0.1.1");
  });

  it("shows the refusal of a file that does not match the release list", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    choose(within(panel).getByTestId("updates-release-file"), file("tenko-release-0.9.9"));
    fireEvent.click(within(panel).getByTestId("updates-upload"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("The file does not match the checksum in the release list.");
    expect(screen.queryByTestId("updates-progress")).toBeNull();
    expect(mockUpdates.attempt).toBeNull();
  });

  it("explains a step-up answer to an upload as well", async () => {
    await signInAdmin();
    backedUpRecently();
    mockUpdates.airGapped = true;
    mockUpdates.stepUpSession = db.currentSessionId;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    choose(within(panel).getByTestId("updates-release-file"), file(mockReleaseFile("0.2.0")));
    fireEvent.click(within(panel).getByTestId("updates-upload"));
    fireEvent.click(within(await screen.findByTestId("dialog-update-install")).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("updates-stepup")).toBeTruthy();
  });

  it("uploads a release list and shows the releases in it", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    mockUpdates.running = "0.2.0";
    await openPage();
    expect(screen.queryByTestId("update-release")).toBeNull();
    // Nothing to install yet: the release file part waits for a newer release.
    expect(screen.getByTestId("updates-upload-wait")).toBeTruthy();

    const manifest = {
      releases: [{ version: "0.3.0", date: "2026-12-01", notes: "### Added\n- Something new.", assets: [] }],
    };
    const panel = screen.getByTestId("updates-upload-panel");
    const button = within(panel).getByTestId("updates-manifest-upload") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    choose(within(panel).getByTestId("updates-manifest-file"), file(JSON.stringify(manifest), "releases.json"));
    expect(button.disabled).toBe(false);
    fireEvent.click(button);

    await waitFor(() => expect(release("0.3.0")).toBeTruthy());
    expect(within(release("0.3.0")).getByText("Something new.")).toBeTruthy();
    expect(screen.getByTestId("updates-manifest-info").getAttribute("data-key")).toBe("uploaded");
    expect(screen.queryByTestId("updates-upload-wait")).toBeNull();
    expect(screen.getByTestId("updates-upload-version")).toBeTruthy();
  });

  it("refuses a release list that is not JSON, and one that is too large, before it is sent", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    choose(within(panel).getByTestId("updates-manifest-file"), file("not json at all", "releases.json"));
    fireEvent.click(within(panel).getByTestId("updates-manifest-upload"));
    expect((await within(panel).findByRole("alert")).textContent).toBe("The file is not valid JSON.");

    const huge = new File([new Uint8Array(1024 * 1024 + 1)], "releases.json");
    choose(within(panel).getByTestId("updates-manifest-file"), huge);
    fireEvent.click(within(panel).getByTestId("updates-manifest-upload"));
    await waitFor(() => expect(within(panel).getByRole("alert").textContent).toContain("too large"));
  });

  it("shows the message of a release list the server refuses", async () => {
    await signInAdmin();
    mockUpdates.airGapped = true;
    await openPage();
    const panel = screen.getByTestId("updates-upload-panel");
    choose(within(panel).getByTestId("updates-manifest-file"), file(JSON.stringify({ nothing: true }), "releases.json"));
    fireEvent.click(within(panel).getByTestId("updates-manifest-upload"));
    expect((await within(panel).findByRole("alert")).textContent).toBe(
      "The release list has a format that this version does not understand.",
    );
  });
});

describe("an install that is under way when the page opens", () => {
  it("follows it from the attempt the server recorded", async () => {
    await signInAdmin();
    mockUpdates.attempt = { from: "0.1.0-dev", to: "0.2.0", state: "restarting", at: iso(Date.now()), job_id: "0190d1c2-0000-7000-8000-0000000c0004" };
    mockUpdates.restartMs = 10_000_000;
    mockUpdates.restart = { version: "0.2.0", readyAt: Date.now() + 10_000_000, rollBack: false };
    await openPage();
    const progress = await screen.findByTestId("updates-progress");
    expect(progress.getAttribute("data-state")).toBe("restarting");
    expect(within(progress).getByText("Restarting into 0.2.0…")).toBeTruthy();
  });

  it("shows a rolled back attempt of the past", async () => {
    await signInAdmin();
    mockUpdates.attempt = {
      from: "0.1.0-dev",
      to: "0.2.0",
      state: "rolled_back",
      at: iso(Date.now() - 3_600_000),
      reason: "upgrade.not_ready",
      job_id: "0190d1c2-0000-7000-8000-0000000c0004",
    };
    await openPage();
    const notice = screen.getByTestId("updates-attempt");
    expect(notice.textContent).toContain("The update from 0.1.0-dev to 0.2.0 was rolled back");
    expect(notice.textContent).toContain("The new version did not become ready in time.");
    // The install is possible again.
    expect(screen.getByTestId("updates-install")).toBeTruthy();
  });
});
