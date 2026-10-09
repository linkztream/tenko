import { screen } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";
import { db, recordEvent } from "../api/mock/db";
import { server } from "../api/mock/node";
import { mockUpdates } from "../api/mock/routes-updates";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { setSessionForTest } from "../auth/session";
import { REFRESH_MS } from "./status";
import { signInAdmin, updatesFail, viewerOnly } from "./testkit";
import UpdateStatusItem from "./UpdateStatusItem";

afterEach(() => {
  vi.useRealTimers();
  setSessionForTest(null);
});

function show() {
  return renderRoute(() => <UpdateStatusItem />, { url: "/", path: "/" });
}

describe("the update item of the status bar", () => {
  it("names the newest version, marks security fixes and links to the updates page", async () => {
    await signInAdmin();
    show();
    const item = await screen.findByTestId("status-update");
    expect(item.textContent).toContain("Update available: 0.2.0");
    expect(item.textContent).toContain("Security fixes");
    expect(item.getAttribute("href")).toBe("/updates");
    expect(item.classList.contains("security")).toBe(true);
  });

  it("has no security mark when no newer release fixes a security issue", async () => {
    await signInAdmin();
    mockUpdates.releases = mockUpdates.releases.map((r) => ({ ...r, security: false }));
    show();
    const item = await screen.findByTestId("status-update");
    expect(item.textContent).toBe("Update available: 0.2.0");
  });

  it("shows nothing when the installation is up to date", async () => {
    await signInAdmin();
    mockUpdates.running = "0.2.0";
    show();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(screen.queryByTestId("status-update")).toBeNull();
  });

  it("shows nothing for an account that may not read the status (403)", async () => {
    await signInAdmin();
    updatesFail(403, "auth.forbidden");
    show();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(screen.queryByTestId("status-update")).toBeNull();
  });

  it("does not even ask when the account is no administrator", async () => {
    await signInAdmin(viewerOnly);
    let asked = 0;
    server.use(
      http.get("/api/v1/system/updates", () => {
        asked += 1;
        return HttpResponse.json({}, { status: 403 });
      }),
    );
    show();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(asked).toBe(0);
    expect(screen.queryByTestId("status-update")).toBeNull();
  });

  it("shows nothing when the server has no update service (503)", async () => {
    await signInAdmin();
    mockUpdates.unavailable = true;
    show();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(screen.queryByTestId("status-update")).toBeNull();
  });

  it("follows the admin events", async () => {
    await signInAdmin();
    const stop = bridgeMockEvents();
    try {
      mockUpdates.running = "0.2.0";
      show();
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(screen.queryByTestId("status-update")).toBeNull();

      // A release list is uploaded elsewhere: the notice appears without a reload.
      mockUpdates.running = "0.1.0-dev";
      recordEvent("admin", { tables: ["sys.updates"] });
      expect((await screen.findByTestId("status-update", {}, { timeout: 3000 })).textContent).toContain("0.2.0");
    } finally {
      stop();
    }
  });

  it("reads the status again every six hours", async () => {
    await signInAdmin();
    mockUpdates.running = "0.2.0";
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    show();
    await vi.waitFor(() => expect(db.revision).toBeGreaterThan(0));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("status-update")).toBeNull();

    mockUpdates.running = "0.1.0-dev";
    await vi.advanceTimersByTimeAsync(REFRESH_MS);
    expect((await screen.findByTestId("status-update")).textContent).toContain("0.2.0");
  });
});
