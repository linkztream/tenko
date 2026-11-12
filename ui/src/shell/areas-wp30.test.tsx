// The areas WP3.0 registers up front: the cluster area on the rail (any signed-in role, no module),
// and the scans route of the discovery module, which has no place on the rail and disappears with
// the module. WP3.11a builds the pages.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { renderApp } from "../app/testing/app";
import { axeViolations } from "../app/testing/axe";
import { setSessionForTest } from "../auth/session";
import { areaEnabled, pathModule, resetModules, setModulesForTest } from "../updates/modules";
import { AREAS } from "./areas";

afterEach(() => {
  resetModules();
  setSessionForTest(null, "loading");
});

const railLinks = (): string[] =>
  within(screen.getByRole("navigation", { name: "Main" }))
    .getAllByRole("link")
    .map((a) => a.textContent?.trim() ?? "");

describe("the cluster area", () => {
  it("sits right after Nodes with a chord of its own, and belongs to no module", () => {
    const ids = AREAS.map((a) => a.id);
    expect(ids.indexOf("cluster")).toBe(ids.indexOf("nodes") + 1);
    const cluster = AREAS.find((a) => a.id === "cluster");
    expect([cluster?.path, cluster?.chord, cluster?.label]).toEqual(["/cluster", "K", "shell.nav.cluster"]);
    const chords = AREAS.map((a) => a.chord);
    expect(new Set(chords).size).toBe(chords.length);

    setModulesForTest([]);
    expect(areaEnabled("cluster")).toBe(true);
    expect(pathModule("/cluster")).toBeNull();
  });

  for (const role of ["admin", "operator", "viewer", "auditor"]) {
    it(`shows ${role} the Cluster entry between Nodes and Settings and opens the page`, async () => {
      await renderApp("/cluster", { roles: [role] });
      const page = await screen.findByTestId("page-cluster", {}, { timeout: 5000 });
      expect(within(page).getByRole("heading", { level: 1 }).textContent).toBe("Cluster");
      expect((await within(page).findByTestId("cluster-summary")).textContent).toContain("Quorum");
      const labels = railLinks();
      expect(labels.indexOf("Cluster")).toBe(labels.indexOf("Nodes") + 1);
      expect(labels.indexOf("Settings")).toBe(labels.indexOf("Cluster") + 1);
      const link = within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Cluster/ });
      expect(link.getAttribute("href")).toBe("/cluster");
      expect(link.classList.contains("active")).toBe(true);
      expect(document.title).toBe("Cluster - Tenko DDI");
    });
  }

  it("stays on the rail while every product module is off", async () => {
    await renderApp("/cluster", { modules: [] });
    await screen.findByTestId("page-cluster", {}, { timeout: 5000 });
    await waitFor(() => expect(railLinks().some((n) => n.startsWith("IPAM"))).toBe(false));
    expect(railLinks()).toContain("Cluster");
    expect(screen.getByTestId("page-cluster")).toBeTruthy();
  });

  it("is reached with G then K and is accessible", async () => {
    const app = await renderApp("/jobs");
    await screen.findByTestId("page-jobs", {}, { timeout: 5000 });
    fireEvent.keyDown(document, { key: "g" });
    fireEvent.keyDown(document, { key: "k" });
    await waitFor(() => expect(app.location()).toBe("/cluster"));
    const page = await screen.findByTestId("page-cluster", {}, { timeout: 5000 });
    expect(await axeViolations(page, { disable: ["region"] })).toEqual([]);
  });
});

describe("the scans route of the discovery module", () => {
  it("is no area of the rail and maps to the discovery module", () => {
    expect(AREAS.some((a) => a.path.startsWith("/scans"))).toBe(false);
    expect(pathModule("/scans")).toBe("discovery");
    expect(pathModule("/scans/0190d1c2-0000-7000-8000-00000000c001")).toBe("discovery");
    expect(pathModule("/scansion")).toBeNull();
  });

  it("opens with and without a scan in the address while Discovery runs", async () => {
    const app = await renderApp("/scans");
    const page = await screen.findByTestId("page-scans", {}, { timeout: 5000 });
    expect(within(page).getByRole("heading", { level: 1 }).textContent).toBe("Scans");
    expect(await within(page).findByTestId("scans-list")).toBeTruthy();
    expect(within(page).getByTestId("scans-probes")).toBeTruthy();
    expect(railLinks().some((n) => n.startsWith("Scans"))).toBe(false);
    expect(document.title).toBe("Scans - Tenko DDI");
    expect(await axeViolations(page, { disable: ["region"] })).toEqual([]);
    app.unmount();

    await renderApp("/scans/0190d1c2-0000-7000-8000-0000000c5001");
    expect(await screen.findByTestId("page-scan", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("opens for a viewer too: any signed-in account", async () => {
    await renderApp("/scans", { roles: ["viewer"] });
    expect(await screen.findByTestId("page-scans", {}, { timeout: 5000 })).toBeTruthy();
  });

  it("is replaced by the page of the switched-off module when Discovery is off", async () => {
    await renderApp("/scans/0190d1c2-0000-7000-8000-00000000c001", { modules: ["ipam", "dns", "dhcp"] });
    const off = await screen.findByTestId("page-module-disabled", {}, { timeout: 5000 });
    expect(off.getAttribute("data-key")).toBe("discovery");
    expect(screen.queryByTestId("page-scans")).toBeNull();
  });

  it("stays reachable while another module is off", async () => {
    await renderApp("/scans", { modules: ["ipam", "discovery"] });
    expect(await screen.findByTestId("page-scans", {}, { timeout: 5000 })).toBeTruthy();
    await waitFor(() => expect(railLinks().some((n) => n.startsWith("DNS"))).toBe(false));
    expect(screen.getByTestId("page-scans")).toBeTruthy();
  });
});
