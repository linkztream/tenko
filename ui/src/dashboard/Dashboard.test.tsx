import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { IPAM_IDS } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { mockMetricsSnapshot } from "../api/mock/metrics-model";
import type { TreeNode } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
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

describe("live metrics", () => {
  it("are shown to an administrator below the tiles of the page", async () => {
    renderRoute(Dashboard, { url: "/" });
    const metrics = await screen.findByTestId("metrics-tiles");
    expect(metrics.querySelectorAll("[data-testid^='metrics-tile-']")).toHaveLength(8);
    // Below the tiles of the page: after the uptime tile, before the cards.
    const page = screen.getByTestId("page-dashboard");
    const order = [...page.querySelectorAll("[data-testid='metrics-tiles'], [data-testid='dashboard-waiting']")];
    expect(order.map((e) => (e as HTMLElement).dataset.testid)).toEqual(["metrics-tiles", "dashboard-waiting"]);
  });

  it("are not shown to a viewer", async () => {
    await signInAlex({ prepare: (user) => (user.roles = ["viewer"]) });
    renderRoute(Dashboard, { url: "/" });
    await screen.findByTestId("dashboard-waiting");
    await waitFor(() => expect(screen.getByTestId("dashboard-audit").querySelectorAll("li").length).toBeGreaterThan(0));
    expect(screen.queryByTestId("metrics-tiles")).toBeNull();
  });
});

// OPS-20: the host tiles of the start page follow the status's disk warning.
/** A stand-in for EventSource whose `metrics` stream sends one sample with the host part and nothing else. */
class HostSamples {
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  private listeners = new Map<string, ((e: Event) => void)[]>();

  constructor(readonly url: string) {
    setTimeout(() => {
      this.onopen?.(new Event("open"));
      if (!url.includes("topics=metrics")) return;
      const snapshot = mockMetricsSnapshot(1, { dns: false, host: true });
      const event = new MessageEvent("metrics", { data: JSON.stringify({ topic: "metrics", kind: "metrics.snapshot", metrics: snapshot }) });
      for (const fn of this.listeners.get("metrics") ?? []) fn(event);
    }, 20);
  }
  addEventListener(type: string, fn: (e: Event) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  close() {}
}

describe("host tiles", () => {
  beforeEach(() => {
    vi.stubGlobal("EventSource", HostSamples);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function warn(low: boolean) {
    const status = await api.get("/api/v1/system/status");
    const warnings = low ? [...status.warnings, { code: "node.disk.low", detail: "the data directory is short of room", params: {} }] : status.warnings;
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ ...status, warnings })));
  }

  it("turn the disk tile to the warning style while the status warns node.disk.low", async () => {
    await warn(true);
    renderRoute(Dashboard, { url: "/" });
    const disk = await screen.findByTestId("metrics-tile-host-disk", undefined, { timeout: 5000 });
    expect(disk.dataset.value).toBe("180");
    expect(screen.getByTestId("metrics-tile-host-cpu").dataset.value).not.toBeUndefined();
    expect(screen.getByTestId("metrics-tile-host-memory").dataset.value).not.toBeUndefined();
    await waitFor(() => expect(disk.dataset.state).toBe("low"), { timeout: 3000 });
    expect(screen.getByTestId("metrics-host-disk-low")).toBeTruthy();
  });

  it("leave the disk tile in the normal style while the status has no warning", async () => {
    await warn(false);
    renderRoute(Dashboard, { url: "/" });
    const disk = await screen.findByTestId("metrics-tile-host-disk", undefined, { timeout: 5000 });
    expect(disk.dataset.value).toBe("180");
    await waitFor(() => expect(screen.getByTestId("dashboard-nodes")).toBeTruthy());
    expect(disk.dataset.state).toBeUndefined();
    expect(screen.queryByTestId("metrics-host-disk-low")).toBeNull();
  });
});
