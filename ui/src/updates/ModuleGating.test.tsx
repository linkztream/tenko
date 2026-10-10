import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { server } from "../api/mock/node";
import { mockUpdates } from "../api/mock/routes-updates";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { Shell } from "../shell/Shell";
import { areaEnabled, moduleRunning, pathModule, setModulesForTest } from "./modules";
import { signInAdmin } from "./testkit";
import { forgetWhatsNew } from "./WhatsNew";

afterEach(() => setSessionForTest(null));

const WITHOUT_IPAM = ["dns", "dhcp", "discovery"] as const;

/** The server runs every module but IPAM. */
function withoutIpam() {
  mockUpdates.modules.running = [...WITHOUT_IPAM];
  mockUpdates.modules.configured = [...WITHOUT_IPAM];
}

/** The shell around a stand-in for the area at `url`. */
async function openShell(url: string, arrange?: () => void) {
  await signInAdmin();
  // No release notes dialog in the way.
  mockUpdates.lastSeen = mockUpdates.running;
  forgetWhatsNew();
  arrange?.();
  const view = renderRoute(() => <Shell><div data-testid="area-child" /></Shell>, { url, path: `/${url.split("/")[1]}/*rest` });
  await screen.findByRole("navigation", { name: "Main" });
  return view;
}

function railNames(): string[] {
  const rail = screen.getByRole("navigation", { name: "Main" });
  return within(rail)
    .getAllByRole("link")
    .map((a) => (a.textContent ?? "").trim());
}

async function openPalette() {
  fireEvent.keyDown(document, { key: "k", ctrlKey: true });
  return screen.findByRole("combobox");
}

function optionTitles(): string[] {
  return screen.queryAllByRole("option").map((o) => (o.textContent ?? "").trim());
}

describe("which modules run", () => {
  it("maps areas and paths to modules, and treats unknown modules as running", () => {
    expect(areaEnabled("ipam")).toBe(true);
    setModulesForTest(WITHOUT_IPAM);
    expect(areaEnabled("ipam")).toBe(false);
    expect(areaEnabled("dns")).toBe(true);
    expect(areaEnabled("topology")).toBe(true);
    setModulesForTest(["ipam"]);
    expect(areaEnabled("dns")).toBe(false);
    expect(areaEnabled("dhcp")).toBe(false);
    expect(areaEnabled("topology")).toBe(false);
    // The dashboard, jobs, audit and settings belong to no module.
    for (const id of ["dashboard", "jobs", "audit", "settings"] as const) expect(areaEnabled(id)).toBe(true);
    expect(moduleRunning("ipam")).toBe(true);
    setModulesForTest(null);
    expect(areaEnabled("dns")).toBe(true);

    expect(pathModule("/ipam/prefixes/192.0.2.0/24")).toBe("ipam");
    expect(pathModule("/search")).toBe("ipam");
    expect(pathModule("/dns/zones/example.test")).toBe("dns");
    expect(pathModule("/topology")).toBe("discovery");
    expect(pathModule("/jobs")).toBeNull();
    expect(pathModule("/")).toBeNull();
    expect(pathModule("/updates")).toBeNull();
  });
});

describe("the shell without IPAM", () => {
  it("shows every area while all modules run", async () => {
    await openShell("/jobs");
    await waitFor(() => expect(railNames()).toHaveLength(11));
    expect(railNames().join(" ")).toContain("IPAM");
  });

  it("hides the rail areas of the modules that do not run", async () => {
    await openShell("/jobs", () => {
      mockUpdates.modules.running = ["ipam", "dns"];
      mockUpdates.modules.configured = ["ipam", "dns"];
    });
    await waitFor(() => expect(railNames().some((n) => n.startsWith("DHCP"))).toBe(false));
    const names = railNames().join(" | ");
    expect(names).toContain("IPAM");
    expect(names).toContain("DNS");
    expect(names).not.toContain("DHCP");
    expect(names).not.toContain("Topology");
    expect(names).not.toContain("Discovery");
    expect(names).toContain("Connectors");
    expect(names).toContain("Nodes");
    expect(names).toContain("Jobs");
    expect(names).toContain("Settings");
  });

  it("hides the IPAM area and the IPAM commands of the palette", async () => {
    await openShell("/jobs", withoutIpam);
    await waitFor(() => expect(railNames().some((n) => n.startsWith("IPAM"))).toBe(false));

    await openPalette();
    const titles = optionTitles();
    expect(titles.some((t) => t.startsWith("DNS"))).toBe(true);
    expect(titles.some((t) => t.startsWith("Jobs"))).toBe(true);
    for (const gone of ["IPAM", "Hosts", "Addresses", "VLANs", "Import"]) {
      expect(titles.some((t) => t.startsWith(gone)), gone).toBe(false);
    }
  });

  it("does not search the inventory without IPAM, and does with it", async () => {
    let searches = 0;
    server.use(
      http.get("/api/v1/search", () => {
        searches += 1;
        return HttpResponse.json({ items: [], next_cursor: null, revision: 1 });
      }),
    );
    await openShell("/jobs", withoutIpam);
    await waitFor(() => expect(railNames().some((n) => n.startsWith("IPAM"))).toBe(false));
    const input = await openPalette();
    fireEvent.input(input, { target: { value: "thermostat" } });
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(searches).toBe(0);
    // No "search everywhere" entry either.
    expect(optionTitles().some((t) => t.startsWith("Search for"))).toBe(false);
  });

  it("searches the inventory while IPAM runs", async () => {
    let searches = 0;
    server.use(
      http.get("/api/v1/search", () => {
        searches += 1;
        return HttpResponse.json({ items: [], next_cursor: null, revision: 1 });
      }),
    );
    await openShell("/jobs");
    const input = await openPalette();
    fireEvent.input(input, { target: { value: "thermostat" } });
    await waitFor(() => expect(searches).toBe(1), { timeout: 3000 });
  });

  it("shows the page of a module that is switched off instead of its area", async () => {
    await openShell("/ipam/addresses", withoutIpam);
    const page = await screen.findByTestId("page-module-disabled");
    expect(page.getAttribute("data-key")).toBe("ipam");
    expect(within(page).getByRole("heading", { level: 1 }).textContent).toBe("IPAM");
    expect(page.textContent).toContain("This module is not enabled on this installation");
    expect(page.textContent).toContain("IPAM is switched off here");
    expect(within(page).getByTestId("module-disabled-home").getAttribute("href")).toBe("/");
    expect(screen.queryByTestId("area-child")).toBeNull();
    expect(await axeViolations(page, { disable: ["region"] })).toEqual([]);
  });

  it("shows the area of a module that runs", async () => {
    await openShell("/dns", withoutIpam);
    await screen.findByTestId("area-child");
    expect(screen.queryByTestId("page-module-disabled")).toBeNull();
  });

  it("lets an area through while the modules are not known yet", async () => {
    await openShell("/ipam/addresses");
    await screen.findByTestId("area-child");
  });

  it("tells administrators in the status bar that a module change waits for a restart", async () => {
    await openShell("/jobs", () => {
      mockUpdates.modules.configured = ["ipam"];
    });
    const item = await screen.findByTestId("status-modules");
    expect(item.textContent).toBe("Restart needed for the module change");
  });
});
