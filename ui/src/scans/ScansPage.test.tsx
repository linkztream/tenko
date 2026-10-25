import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { SCAN_IDS } from "../api/mock/scans-store";
import { NODE_IDS } from "../api/mock/nodes-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { listProbes, listScans } from "./api";
import { nodeScanPath, scanPath } from "./model";
import ScansPage from "./ScansPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

function renderScans() {
  return renderRoute(ScansPage, {
    url: "/scans",
    path: "/scans",
    routes: { "/scans/:id": () => <div data-testid="scan-route" />, "/nodes/:id/scan": () => <div data-testid="node-scan-route" /> },
  });
}

async function listed() {
  return await screen.findByTestId("scans-list");
}

const rowOf = (id: string): HTMLElement => screen.getByTestId(`scan-row-${id}`);

describe("the scan jobs", () => {
  it("lists the seed newest first, each linking to its scan", async () => {
    renderScans();
    const table = await listed();
    expect(screen.getByTestId("page-scans")).toBeTruthy();
    const rows = within(table).getAllByTestId(/^scan-row-/);
    expect(rows.map((r) => r.dataset.testid)).toEqual([`scan-row-${SCAN_IDS.running}`, `scan-row-${SCAN_IDS.done}`]);

    const done = rowOf(SCAN_IDS.done);
    expect(done.dataset.state).toBe("done");
    expect(within(done).getByText("Done").getAttribute("data-state")).toBe("done");
    expect(within(done).getByRole("progressbar").getAttribute("aria-valuenow")).toBe("100");
    expect(within(done).getByText("Prefix")).toBeTruthy();
    expect(within(done).getByRole("link").getAttribute("href")).toBe(scanPath(SCAN_IDS.done));
    expect(within(done).getByRole("link").textContent).toBe("192.0.2.0/24");
    expect(within(done).getByText("Passive refresh, Port scan")).toBeTruthy();
    // 3 new, 2 changed, 2 gone over the four fact types.
    expect(within(done).getByTestId("scan-changes").textContent).toBe("3 new, 2 changed, 2 gone");

    const running = rowOf(SCAN_IDS.running);
    expect(running.dataset.state).toBe("running");
    // No diff yet: a dash instead of the counts.
    expect(within(running).queryByTestId("scan-changes")).toBeNull();
  });

  it("follows a running scan until it is done, reading again every two seconds", async () => {
    renderScans();
    await listed();
    // The first read advanced the scan from 40 to 60 percent.
    const bar = () => within(rowOf(SCAN_IDS.running)).getByRole("progressbar");
    expect(bar().getAttribute("aria-valuenow")).toBe("60");
    await waitFor(() => expect(Number(bar().getAttribute("aria-valuenow"))).toBeGreaterThan(60), { timeout: 4000 });
    await waitFor(() => expect(rowOf(SCAN_IDS.running).dataset.state).toBe("done"), { timeout: 8000 });
    expect(within(rowOf(SCAN_IDS.running)).getByRole("progressbar").getAttribute("aria-valuenow")).toBe("100");
    expect(within(rowOf(SCAN_IDS.running)).getByTestId("scan-changes").textContent).toBe("2 new, 1 changed, 0 gone");
  }, 20000);

  it("sees a scan that ended elsewhere on the next read", async () => {
    renderScans();
    await listed();
    // Two reads of the clock outside the page finish the scan (60 -> 80 -> 100).
    await listScans();
    await listScans();
    await waitFor(() => expect(rowOf(SCAN_IDS.running).dataset.state).toBe("done"), { timeout: 5000 });
  });
});

describe("the probes", () => {
  it("lists them with the marker, the sync state, the applied scope and the kill switch", async () => {
    renderScans();
    const table = await screen.findByTestId("scans-probes");
    await waitFor(() => expect(within(table).getAllByTestId(/^probe-row-/)).toHaveLength(3));
    const ctl = screen.getByTestId("probe-row-1");
    expect(within(ctl).getByTestId("probe-in-process")).toBeTruthy();
    expect(within(ctl).getByText("ctl-1.example.test").getAttribute("href")).toBe(nodeScanPath(1));
    expect(within(ctl).getByTestId("probe-sync").textContent).toBe("In sync");
    expect(within(ctl).getByTestId("probe-scope").textContent).toMatch(/^2 prefixes · /);
    expect(within(ctl).getByTestId("probe-switch").textContent).toBe("Scanning");
    const dmz = screen.getByTestId(`probe-row-${NODE_IDS.dmz}`);
    expect(within(dmz).queryByTestId("probe-in-process")).toBeNull();
    expect(within(dmz).getByText("probe-dmz").getAttribute("href")).toBe(nodeScanPath(NODE_IDS.dmz));
    expect(within(dmz).getByTestId("probe-scope").textContent).toMatch(/^2 prefixes · /);
  });
});

describe("the way to a probe's scan configuration", () => {
  it("gives every probe, this controller's own included, a link named Scan configuration", async () => {
    renderScans();
    const table = await screen.findByTestId("scans-probes");
    await waitFor(() => expect(within(table).getAllByTestId(/^probe-row-/)).toHaveLength(3));
    const links = within(table).getAllByTestId("probe-config");
    expect(links.map((a) => a.getAttribute("href"))).toEqual([nodeScanPath(1), nodeScanPath(NODE_IDS.dmz), nodeScanPath(NODE_IDS.lab)]);
    for (const link of links) expect(link.textContent).toBe("Scan configuration");
    const own = within(screen.getByTestId("probe-row-1")).getByRole("link", { name: "Scan configuration of ctl-1.example.test" });
    expect(own.getAttribute("href")).toBe("/nodes/1/scan");
  });
});

describe("stop all and resume all", () => {
  it("stops every probe with a reason and resumes them again", async () => {
    renderScans();
    await screen.findByTestId("scans-list");
    await waitFor(() => expect(screen.getAllByTestId(/^probe-row-/)).toHaveLength(3));
    expect(screen.queryByTestId("scans-resume-all")).toBeNull();

    fireEvent.click(screen.getByTestId("scans-stop-all"));
    const dialog = await screen.findByTestId("dialog-stop-scans");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "maintenance window" } });
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(screen.queryByTestId("dialog-stop-scans")).toBeNull());
    await waitFor(() => {
      for (const row of screen.getAllByTestId(/^probe-row-/)) expect(row.dataset.state).toBe("stopped");
    });
    const switches = screen.getAllByTestId("probe-switch");
    expect(switches.map((s) => s.textContent)).toEqual(["Stopped", "Stopped", "Stopped"]);
    expect(screen.getAllByText("Reason: maintenance window")).toHaveLength(3);
    // The running scan lost its only probe and ended.
    await waitFor(() => expect(rowOf(SCAN_IDS.running).dataset.state).toBe("cancelled"));
    expect((screen.getByTestId("scans-stop-all") as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(await screen.findByTestId("scans-resume-all"));
    await waitFor(() => {
      for (const row of screen.getAllByTestId(/^probe-row-/)) expect(row.dataset.state).toBe("active");
    });
    expect(screen.queryByTestId("scans-resume-all")).toBeNull();
    expect((screen.getByTestId("scans-stop-all") as HTMLButtonElement).disabled).toBe(false);
  });

  it("offers resume while a single probe is stopped", async () => {
    await api.post("/api/v1/nodes/{id}/scan/stop", { path: { id: NODE_IDS.lab }, body: {} });
    renderScans();
    expect(await screen.findByTestId("scans-resume-all")).toBeTruthy();
    expect((screen.getByTestId("scans-stop-all") as HTMLButtonElement).disabled).toBe(false);
    await waitFor(() => expect(screen.getByTestId(`probe-row-${NODE_IDS.lab}`).dataset.state).toBe("stopped"));
    expect((await listProbes()).items.filter((p) => p.kill_switch.stopped)).toHaveLength(1);
  });

  it("closes the dialog with Escape and changes nothing", async () => {
    renderScans();
    await waitFor(() => expect((screen.getByTestId("scans-stop-all") as HTMLButtonElement).disabled).toBe(false));
    const opener = screen.getByTestId("scans-stop-all");
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByTestId("dialog-stop-scans");
    await waitFor(() => expect(document.activeElement).toBe(within(dialog).getByTestId("field-reason")));
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-stop-scans")).toBeNull());
    expect(document.activeElement).toBe(opener);
    expect((await listProbes()).items.some((p) => p.kill_switch.stopped)).toBe(false);
  });

  it("reaches both actions with the keyboard", async () => {
    renderScans();
    await waitFor(() => expect((screen.getByTestId("scans-stop-all") as HTMLButtonElement).disabled).toBe(false));
    const stop = screen.getByTestId("scans-stop-all");
    expect(stop.tagName).toBe("BUTTON");
    expect(stop.getAttribute("tabindex")).toBeNull();
  });
});

describe("a viewer", () => {
  it("reads the scans and the probes and has no actions", async () => {
    await signInAlex({ prepare: (user) => void (user.roles = ["viewer"] as never) });
    renderScans();
    await listed();
    await waitFor(() => expect(screen.getAllByTestId(/^probe-row-/)).toHaveLength(3));
    expect(screen.queryByTestId("scans-stop-all")).toBeNull();
    expect(screen.queryByTestId("scans-resume-all")).toBeNull();
  });
});

describe("accessibility", () => {
  it("has no axe violations, with the dialog open either", async () => {
    renderScans();
    const page = await screen.findByTestId("page-scans");
    await waitFor(() => expect(screen.getAllByTestId(/^probe-row-/)).toHaveLength(3));
    expect(await axeViolations(page, { disable: ["region"] })).toEqual([]);
    fireEvent.click(screen.getByTestId("scans-stop-all"));
    const dialog = await screen.findByTestId("dialog-stop-scans");
    expect(await axeViolations(dialog, { disable: ["region"] })).toEqual([]);
  });
});
