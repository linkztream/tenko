import { screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { mockUpdates } from "../api/mock/routes-updates";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import Dashboard from "../dashboard/Dashboard";
import { resetModules, setModulesForTest } from "./modules";
import { signInAdmin, viewerOnly } from "./testkit";

afterEach(() => {
  setSessionForTest(null);
  resetModules();
});

async function openDashboard() {
  const view = renderRoute(Dashboard, { url: "/", path: "/" });
  await screen.findByTestId("page-dashboard");
  return view;
}

describe("the update card of the dashboard", () => {
  it("names the newest version, its marks and links to the updates page", async () => {
    await signInAdmin();
    await openDashboard();
    const card = await screen.findByTestId("dashboard-update");
    expect(within(card).getByRole("heading", { name: "Update available" })).toBeTruthy();
    expect(card.textContent).toContain("Version 0.2.0 is available. This installation runs 0.1.0-dev.");
    const marks = within(card).getAllByTestId("update-mark");
    expect(marks.map((m) => m.getAttribute("data-key"))).toEqual(["security", "action"]);
    expect(marks.map((m) => m.textContent)).toEqual(["Security fixes", "Action required"]);
    expect(within(card).getByTestId("dashboard-update-open").getAttribute("href")).toBe("/updates");
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });

  it("shows nothing when nothing is newer", async () => {
    await signInAdmin();
    mockUpdates.running = "0.2.0";
    await openDashboard();
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(screen.queryByTestId("dashboard-update")).toBeNull();
  });

  it("shows nothing to an account that may not read updates", async () => {
    await signInAdmin(viewerOnly);
    await openDashboard();
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(screen.queryByTestId("dashboard-update")).toBeNull();
  });

  it("shows nothing when the server has no update service", async () => {
    await signInAdmin();
    mockUpdates.unavailable = true;
    await openDashboard();
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(screen.queryByTestId("dashboard-update")).toBeNull();
  });
});

describe("the dashboard and the modules", () => {
  it("shows the IPAM cards while IPAM runs", async () => {
    await signInAdmin();
    await openDashboard();
    expect(await screen.findByTestId("dashboard-health-alarms")).toBeTruthy();
    expect(await screen.findByTestId("dashboard-utilization")).toBeTruthy();
    expect(screen.getByTestId("dashboard-claim")).toBeTruthy();
    expect(screen.getByTestId("dashboard-import")).toBeTruthy();
  });

  it("hides the IPAM cards and actions without IPAM, and keeps the rest", async () => {
    await signInAdmin();
    setModulesForTest(["dns", "dhcp", "discovery"]);
    await openDashboard();
    await screen.findByTestId("dashboard-attention");
    expect(screen.getByTestId("dashboard-audit")).toBeTruthy();
    expect(screen.queryByTestId("dashboard-health-alarms")).toBeNull();
    expect(screen.queryByTestId("dashboard-health-v4")).toBeNull();
    expect(screen.queryByTestId("dashboard-utilization")).toBeNull();
    expect(screen.queryByTestId("dashboard-claim")).toBeNull();
    expect(screen.queryByTestId("dashboard-new-prefix")).toBeNull();
    expect(screen.queryByTestId("dashboard-import")).toBeNull();
    expect(screen.queryByText("IPv4 addresses")).toBeNull();
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });
});

describe("the restart notice of the dashboard", () => {
  it("tells an administrator what runs now and what runs after the restart", async () => {
    await signInAdmin();
    mockUpdates.modules.configured = ["dns", "dhcp"];
    await openDashboard();
    const notice = await screen.findByTestId("dashboard-modules-restart");
    expect(notice.textContent).toContain("Restart needed");
    expect(notice.textContent).toContain("Running now: IPAM, DNS, DHCP, and Discovery.");
    expect(notice.textContent).toContain("After the restart: DNS and DHCP.");
  });

  it("shows nothing while no change waits", async () => {
    await signInAdmin();
    await openDashboard();
    await waitFor(() => expect(screen.getByTestId("dashboard-attention")).toBeTruthy());
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(screen.queryByTestId("dashboard-modules-restart")).toBeNull();
  });

  it("is for administrators", async () => {
    await signInAdmin(viewerOnly);
    mockUpdates.modules.configured = ["dns"];
    await openDashboard();
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(screen.queryByTestId("dashboard-modules-restart")).toBeNull();
  });
});
