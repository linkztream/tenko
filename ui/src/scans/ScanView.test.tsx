import { screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SCAN_IDS, scansState } from "../api/mock/scans-store";
import { NODE_IDS } from "../api/mock/nodes-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { getScan } from "./api";
import { nodeScanPath, SCANS_PATH, scanPath } from "./model";
import ScanView from "./ScanView";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

function renderScan(id: string) {
  return renderRoute(ScanView, {
    url: scanPath(id),
    path: "/scans/:id",
    routes: { "/scans": () => <div data-testid="scans-route" />, "/nodes/:id/scan": () => <div data-testid="node-scan-route" /> },
  });
}

const cell = (row: HTMLElement, col: string): string => row.querySelector(`[data-col='${col}']`)?.textContent ?? "";

describe("a finished scan", () => {
  it("shows the target, the state, the part of the probe and the diff", async () => {
    renderScan(SCAN_IDS.done);
    const page = await screen.findByTestId("page-scan");
    await waitFor(() => expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain("Scan of 192.0.2.0/24"));
    await waitFor(() => expect(screen.getByTestId("scan-state").textContent).toBe("Done"));
    expect(screen.getByTestId("scan-state").dataset.state).toBe("done");
    expect(screen.getByTestId("scan-progress").getAttribute("aria-valuenow")).toBe("100");
    expect(within(screen.getByTestId("scan-facts")).getByText("Passive refresh, Port scan")).toBeTruthy();

    // The part of the controller's own probe, with its name once the probes are listed.
    const part = screen.getByTestId("scan-probe-1");
    expect(part.dataset.state).toBe("done");
    await waitFor(() => expect(within(part).getByRole("link").textContent).toBe("ctl-1.example.test"));
    expect(within(part).getByRole("link").getAttribute("href")).toBe(nodeScanPath(1));
    expect(within(part).getByText("4 of 4")).toBeTruthy();
    expect(within(part).getByText("passive_refresh, port_scan")).toBeTruthy();
    expect(within(part).getByRole("progressbar").getAttribute("aria-valuenow")).toBe("100");
  });

  it("totals the diff per fact type and lists the changed facts", async () => {
    renderScan(SCAN_IDS.done);
    const diff = await screen.findByTestId("scan-diff");
    await within(diff).findByTestId("diff-row-0");
    const totals = within(diff).getByTestId("diff-total-address");
    expect(["new", "changed", "gone", "unchanged"].map((c) => cell(totals, c))).toEqual(["1", "1", "1", "22"]);
    expect(within(totals).getByRole("rowheader").textContent).toBe("Address");
    const all = within(diff).getByTestId("diff-total-all");
    expect(["new", "changed", "gone", "unchanged"].map((c) => cell(all, c))).toEqual(["3", "2", "2", "70"]);

    const items = within(diff).getAllByTestId(/^diff-row-/);
    expect(items).toHaveLength(7);
    const first = screen.getByTestId("diff-row-0");
    expect(first.dataset.state).toBe("new");
    expect(cell(first, "type")).toBe("Address");
    expect(cell(first, "subject")).toBe("192.0.2.41");
    expect(cell(first, "before")).toBe("none");
    expect(cell(first, "after")).toBe("192.0.2.41 from 00:00:5e:00:53:41");
    expect(cell(first, "change")).toBe("New");

    const changed = screen.getByTestId("diff-row-3");
    expect(changed.dataset.state).toBe("changed");
    expect(cell(changed, "before")).toBe("192.0.2.12 from 00:00:5e:00:53:12");
    expect(cell(changed, "after")).toBe("192.0.2.12 from 00:00:5e:00:53:92");

    const ports = screen.getByTestId("diff-row-4");
    expect(cell(ports, "type")).toBe("Open ports");
    expect(cell(ports, "before")).toBe("TCP 22, 80");
    expect(cell(ports, "after")).toBe("TCP 22, 80, 443 · TLS on 443");

    const gone = screen.getByTestId("diff-row-6");
    expect(gone.dataset.state).toBe("gone");
    expect(cell(gone, "type")).toBe("Name");
    expect(cell(gone, "before")).toBe("old-camera.example.test");
    expect(cell(gone, "after")).toBe("none");
    expect(screen.queryByTestId("scan-diff-truncated")).toBeNull();
  });

  it("notes a diff that was cut", async () => {
    const scan = scansState().scans.find((s) => s.view.id === SCAN_IDS.done);
    if (scan?.view.diff) scan.view.diff.truncated = true;
    renderScan(SCAN_IDS.done);
    expect((await screen.findByTestId("scan-diff-truncated")).textContent).toContain("only the first changes");
  });
});

describe("a running scan", () => {
  it("shows the progress of the probe and follows it to the diff", async () => {
    renderScan(SCAN_IDS.running);
    await screen.findByTestId("scan-progress");
    expect(screen.getByTestId("scan-state").dataset.state).toBe("running");
    const part = screen.getByTestId(`scan-probe-${NODE_IDS.dmz}`);
    expect(part.dataset.state).toBe("running");
    await waitFor(() => expect(within(part).getByRole("link").textContent).toBe("probe-dmz"));
    expect(screen.getByTestId("scan-diff-waiting").textContent).toBe("The findings appear when the scan has finished.");

    await waitFor(() => expect(screen.getByTestId("scan-state").dataset.state).toBe("done"), { timeout: 9000 });
    expect(screen.getByTestId("scan-progress").getAttribute("aria-valuenow")).toBe("100");
    expect(screen.getByTestId(`scan-probe-${NODE_IDS.dmz}`).dataset.state).toBe("done");
    expect(screen.getAllByTestId(/^diff-row-/)).toHaveLength(3);
    expect(screen.queryByTestId("scan-diff-waiting")).toBeNull();
  }, 20000);

  it("takes the end the scan reached elsewhere on the next read", async () => {
    renderScan(SCAN_IDS.running);
    await screen.findByTestId("scan-progress");
    await getScan(SCAN_IDS.running);
    await getScan(SCAN_IDS.running);
    await waitFor(() => expect(screen.getByTestId("scan-state").dataset.state).toBe("done"), { timeout: 5000 });
  });
});

describe("a scan that does not exist", () => {
  it("shows a not-found notice and a way back", async () => {
    renderScan("0190d1c2-0000-7000-8000-0000000c50ff");
    const note = await screen.findByTestId("scan-not-found");
    expect(note.textContent).toContain("Scan not found");
    expect(screen.queryByTestId("scan-diff")).toBeNull();
    expect(screen.getByRole("link", { name: "All scans" }).getAttribute("href")).toBe(SCANS_PATH);
  });

  it("shows other refusals as an error notice", async () => {
    renderScan("not-a-uuid");
    const note = await screen.findByTestId("error-notice");
    expect(note.dataset.code).toBe("sys.invalid_request");
  });
});

describe("a viewer and the keyboard", () => {
  it("reads a scan like anyone else, and every link is a link", async () => {
    await signInAlex({ prepare: (user) => void (user.roles = ["viewer"] as never) });
    renderScan(SCAN_IDS.done);
    await screen.findByTestId("diff-row-0");
    for (const link of screen.getAllByRole("link")) expect(link.getAttribute("href")).toBeTruthy();
  });

  it("has no axe violations", async () => {
    renderScan(SCAN_IDS.done);
    const page = await screen.findByTestId("page-scan");
    await screen.findByTestId("diff-row-0");
    expect(await axeViolations(page, { disable: ["region"] })).toEqual([]);
  });
});
