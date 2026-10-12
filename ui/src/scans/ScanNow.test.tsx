import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { IPAM_IDS } from "../api/mock/ipam/api";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { resetModules, setModulesForTest } from "../updates/modules";
import { listScans } from "./api";
import { type ScanNowTarget, scanPath } from "./model";
import ScanNow from "./ScanNow";

const LAN: ScanNowTarget = { kind: "network", value: "192.0.2.0/24", label: "192.0.2.0/24" };
const UNCOVERED: ScanNowTarget = { kind: "network", value: "2001:db8:ffff::/48", label: "2001:db8:ffff::/48" };

beforeEach(async () => {
  await signInAlex();
  setModulesForTest(["ipam", "dns", "dhcp", "discovery"]);
});

afterEach(() => {
  resetModules();
  setSessionForTest(null);
});

function renderNow(target: ScanNowTarget = LAN) {
  return renderRoute(() => <ScanNow {...target} />, {
    url: "/ipam",
    path: "/ipam",
    routes: { "/scans/:id": () => <div data-testid="scan-route" /> },
  });
}

async function openDialog(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByTestId("scan-now"));
  return await screen.findByTestId("dialog-scan-now");
}

const checkbox = (kind: string): HTMLInputElement => screen.getByTestId(`scan-now-kind-${kind}`) as HTMLInputElement;

describe("the button", () => {
  it("opens a dialog that names the target, with passive refresh ticked", async () => {
    renderNow();
    const dialog = await openDialog();
    expect(within(dialog).getByRole("heading", { level: 2 }).textContent).toBe("Scan 192.0.2.0/24");
    expect(dialog.getAttribute("aria-label")).toBe("Scan 192.0.2.0/24");
    expect(checkbox("passive_refresh").checked).toBe(true);
    expect(checkbox("port_scan").checked).toBe(false);
    expect(checkbox("snmp_poll").checked).toBe(false);
    expect(checkbox("os_fingerprint").checked).toBe(false);
    expect((screen.getByTestId("scan-now-deadline") as HTMLSelectElement).value).toBe("600");
  });

  it("is shown to operators and administrators only", async () => {
    await signInAlex({ prepare: (user) => void (user.roles = ["viewer"] as never) });
    renderNow();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByTestId("scan-now")).toBeNull();
  });

  it("is shown to an operator", async () => {
    await signInAlex({ prepare: (user) => void (user.roles = ["operator"] as never) });
    renderNow();
    expect(await screen.findByTestId("scan-now")).toBeTruthy();
  });

  it("is not shown while the Discovery module is off", async () => {
    setModulesForTest(["ipam", "dns", "dhcp"]);
    renderNow();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByTestId("scan-now")).toBeNull();
  });
});

describe("starting a scan", () => {
  it("creates a scan for 192.0.2.0/24 and links to it", async () => {
    renderNow();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));

    const started = await screen.findByTestId("scan-now-started");
    expect(started.textContent).toContain("Scan started");
    expect(started.textContent).toContain("1 probe is working on it.");
    const scans = (await listScans()).items;
    const created = scans.find((s) => s.target.value === "192.0.2.0/24");
    expect(created).toBeTruthy();
    expect(created?.kinds).toEqual(["passive_refresh"]);
    expect(created?.networks).toEqual(["192.0.2.0/24"]);
    expect(created?.probes.map((p) => p.node)).toEqual([1]);
    expect(screen.getByTestId("scan-now-follow").getAttribute("href")).toBe(scanPath(created?.id ?? ""));
    expect(new Date(created?.deadline ?? 0).getTime() - new Date(created?.created_at ?? 0).getTime()).toBe(600_000);
    expect(await axeViolations(screen.getByTestId("dialog-scan-now"), { disable: ["region"] })).toEqual([]);

    fireEvent.click(screen.getByTestId("scan-now-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-scan-now")).toBeNull());
  });

  it("sends the kinds ticked, in the order of the document, and the deadline chosen", async () => {
    renderNow();
    const dialog = await openDialog();
    fireEvent.click(checkbox("os_fingerprint"));
    fireEvent.click(checkbox("port_scan"));
    fireEvent.change(within(dialog).getByTestId("scan-now-deadline"), { target: { value: "60" } });
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));
    await screen.findByTestId("scan-now-started");
    const created = (await listScans()).items.find((s) => s.target.value === "192.0.2.0/24");
    expect(created?.kinds).toEqual(["passive_refresh", "port_scan", "os_fingerprint"]);
    expect(new Date(created?.deadline ?? 0).getTime() - new Date(created?.created_at ?? 0).getTime()).toBe(60_000);
  });

  it("scans a prefix by its identifier", async () => {
    renderNow({ kind: "prefix", value: IPAM_IDS.prefix.lan, label: "192.0.2.0/24 (LAN)" });
    const dialog = await openDialog();
    expect(dialog.getAttribute("aria-label")).toBe("Scan 192.0.2.0/24 (LAN)");
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));
    await screen.findByTestId("scan-now-started");
    const created = (await listScans()).items.find((s) => s.target.value === IPAM_IDS.prefix.lan);
    expect(created?.target.kind).toBe("prefix");
  });

  it("asks for at least one kind", async () => {
    renderNow();
    const dialog = await openDialog();
    fireEvent.click(checkbox("passive_refresh"));
    expect((within(dialog).getByTestId("scan-now-start") as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).getByRole("alert").textContent).toBe("Choose at least one kind.");
    fireEvent.click(checkbox("snmp_poll"));
    expect((within(dialog).getByTestId("scan-now-start") as HTMLButtonElement).disabled).toBe(false);
    expect(within(dialog).queryByRole("alert")).toBeNull();
  });
});

describe("refusals", () => {
  it("says that no probe covers a prefix and keeps the dialog open", async () => {
    renderNow(UNCOVERED);
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));
    const note = await within(dialog).findByTestId("error-notice");
    expect(note.dataset.code).toBe("scan.job.no_probe");
    expect(note.textContent).toBe("No probe covers this target. Add its network to the prefixes of a probe first.");
    expect(screen.queryByTestId("scan-now-started")).toBeNull();
    expect((await listScans()).items.some((s) => s.target.value === UNCOVERED.value)).toBe(false);
    expect((within(dialog).getByTestId("scan-now-start") as HTMLButtonElement).disabled).toBe(false);
    expect(await axeViolations(dialog, { disable: ["region"] })).toEqual([]);
  });

  it("says that a prefix does not exist", async () => {
    renderNow({ kind: "prefix", value: "0190d1c2-0000-7000-8000-00000c0000ff", label: "gone" });
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));
    const note = await within(dialog).findByTestId("error-notice");
    expect(note.dataset.code).toBe("scan.job.target");
    expect(note.textContent).toContain("cannot be scanned");
  });

  it("reports a scan that every stopped probe refused", async () => {
    await api.post("/api/v1/scans/stop", { body: {} });
    renderNow();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("scan-now-start"));
    const note = await within(dialog).findByTestId("scan-now-started");
    expect(note.textContent).toContain("Scanning is stopped: the kill switch is on.");
    expect(note.getAttribute("role")).toBe("alert");
    const created = (await listScans()).items.find((s) => s.target.value === "192.0.2.0/24");
    expect(created?.state).toBe("failed");
    expect(created?.error).toBe("scan.stopped");
  });
});

describe("the keyboard", () => {
  it("opens from the button and closes with Escape, returning the focus to the button", async () => {
    renderNow();
    const button = await screen.findByTestId("scan-now");
    expect(button.tagName).toBe("BUTTON");
    button.focus();
    fireEvent.click(button);
    const dialog = await screen.findByTestId("dialog-scan-now");
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-scan-now")).toBeNull());
    expect(document.activeElement).toBe(button);
  });

  it("starts the scan from the form with Enter", async () => {
    renderNow();
    const dialog = await openDialog();
    fireEvent.submit(dialog.querySelector("form") as HTMLFormElement);
    expect(await screen.findByTestId("scan-now-started")).toBeTruthy();
  });

  it("has no axe violations on the button or in the dialog", async () => {
    const view = renderNow();
    await screen.findByTestId("scan-now");
    expect(await axeViolations(view.container, { disable: ["region"] })).toEqual([]);
    const dialog = await openDialog();
    expect(await axeViolations(dialog, { disable: ["region"] })).toEqual([]);
  });
});
