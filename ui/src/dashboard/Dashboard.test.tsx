import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { IPAM_IDS } from "../api/mock/ipam/api";
import type { TreeNode } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import AlarmStatus from "../ipam/AlarmStatus";
import { writeQuery } from "../ipam/plan/describe";
import Dashboard from "./Dashboard";

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
});

/** The networks of the default VRF that the seed puts above a threshold. */
async function seededAlarms(): Promise<TreeNode[]> {
  const tree = await api.get("/api/v1/prefixes/tree", { query: { vrf: IPAM_IDS.vrf.default } });
  return tree.nodes.filter((n) => n.level !== "normal");
}

/** Fills the cameras network (203.0.113.192/28, thresholds 70 and 90 percent) to critical. */
async function fillCameras() {
  const used = new Set((await api.get("/api/v1/addresses", { query: { vrf: IPAM_IDS.vrf.default, limit: 500 } })).items.map((a) => a.ip));
  for (let i = 193; i <= 206; i++) {
    const ip = `203.0.113.${i}`;
    if (used.has(ip)) continue;
    await api.post("/api/v1/addresses", { query: writeQuery(false, ["*"]), body: { ip, vrf: IPAM_IDS.vrf.default, status: "active" } as never });
  }
}

describe("dashboard", () => {
  it("shows utilization per tenant and VRF, the alarms, the jobs waiting for a manual step and the recent audit", async () => {
    const expected = await seededAlarms();
    renderRoute(Dashboard, { url: "/" });
    const use = await screen.findByTestId("dashboard-utilization");
    await waitFor(() => expect(within(use).getAllByRole("region").length).toBe(2));
    const defaultVrf = use.querySelector(`[data-vrf="${IPAM_IDS.vrf.default}"]`) as HTMLElement;
    expect(defaultVrf.getAttribute("aria-label")).toMatch(/default/);
    expect(within(defaultVrf).getByRole("link", { name: /192\.0\.2\.0\/24/ }).getAttribute("href")).toBe(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.default));

    const alarms = screen.getByTestId("dashboard-alarms");
    await waitFor(() => expect(alarms.querySelectorAll("li").length).toBe(expected.length));
    for (const node of expected) {
      const li = alarms.querySelector(`li[data-key="${node.cidr}"]`) as HTMLElement;
      expect(li.dataset.level).toBe(node.level);
    }

    const waiting = screen.getByTestId("dashboard-waiting");
    await waitFor(() => expect(waiting.querySelectorAll("li").length).toBeGreaterThan(0));
    const job = waiting.querySelector("li") as HTMLElement;
    expect(within(job).getByRole("link").getAttribute("href")).toBe(paths.job(job.dataset.id!));

    const audit = screen.getByTestId("dashboard-audit");
    await waitFor(() => expect(audit.querySelectorAll("li").length).toBeGreaterThan(0));
    expect(audit.querySelectorAll("li").length).toBeLessThanOrEqual(8);
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });

  it("lists a network that crosses its critical threshold as soon as the alarm event arrives", async () => {
    stopBridge = bridgeMockEvents();
    renderRoute(Dashboard, { url: "/" });
    const alarms = await screen.findByTestId("dashboard-alarms");
    await waitFor(() => expect(screen.getByTestId("dashboard-utilization").querySelectorAll("[data-vrf]").length).toBe(2));
    await fillCameras();
    await waitFor(() => expect((alarms.querySelector('li[data-key="203.0.113.192/28"]') as HTMLElement | null)?.dataset.level).toBe("critical"), {
      timeout: 3000,
    });
    // Critical alarms come first.
    expect((alarms.querySelector("li") as HTMLElement).dataset.level).toBe("critical");
  });

  it("starts the quick actions: claim an address asks for the network first, new prefix opens the form, import links to the wizard", async () => {
    renderRoute(Dashboard, { url: "/" });
    const claim = (await screen.findByTestId("dashboard-claim")) as HTMLButtonElement;
    await waitFor(() => expect(claim.disabled).toBe(false));
    expect(screen.getByTestId("dashboard-import").getAttribute("href")).toBe(paths.imports());
    fireEvent.click(claim);
    const picker = await screen.findByRole("dialog");
    await waitFor(() => expect(picker.textContent).toContain("192.0.2.0/24"));
    fireEvent.keyDown(picker, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.click(screen.getByTestId("dashboard-new-prefix"));
    expect(await screen.findByRole("dialog")).toBeTruthy();
  });
});

describe("alarm status", () => {
  it("shows the number of alarms and the critical ones, links to the dashboard and follows alarm events", async () => {
    stopBridge = bridgeMockEvents();
    const before = await seededAlarms();
    renderRoute(AlarmStatus, { url: "/" });
    if (before.length === 0) expect(screen.queryByTestId("status-alarms")).toBeNull();
    await fillCameras();
    const link = await screen.findByTestId("status-alarms", undefined, { timeout: 3000 });
    expect(link.getAttribute("href")).toBe(`${paths.dashboard()}#alarms`);
    await waitFor(() => expect(link.classList.contains("crit")).toBe(true), { timeout: 3000 });
    expect(link.textContent).toMatch(/critical/i);
    expect(await axeViolations(link.parentElement as HTMLElement)).toEqual([]);
  });
});
