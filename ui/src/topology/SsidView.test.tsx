import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { HOST_IDS } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { mockTopologyDecisions } from "../api/mock/topology-decisions";
import { mockVlanController, TOPOLOGY_IDS, TOPOLOGY_SSIDS } from "../api/mock/topology-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { SsidView } from "./SsidView";

const T = TOPOLOGY_IDS;
const S = TOPOLOGY_SSIDS;
const PROBLEM = { "content-type": "application/problem+json" };

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
  vi.unstubAllGlobals();
});

function renderSsids(overrides: { readOnly?: boolean } = {}) {
  const onShowNode = vi.fn<(id: string) => void>();
  const view = renderRoute(
    () => <SsidView readOnly={overrides.readOnly ?? false} vlanStyle={() => undefined} onShowNode={onShowNode} />,
    { url: "/topology?view=ssids", path: "/topology" },
  );
  return { ...view, onShowNode };
}

/** Renders the view and waits until the three SSIDs of the lab are listed. */
async function openSsids(overrides: { readOnly?: boolean } = {}) {
  const view = renderSsids(overrides);
  await waitFor(() => expect(rows()).toHaveLength(3));
  return view;
}

const rows = (): HTMLElement[] => screen.queryAllByTestId("ssid-row");

function row(ssid: string): HTMLElement {
  const found = rows().find((r) => r.dataset.ssid === ssid);
  if (!found) throw new Error(`no SSID ${ssid} in the view`);
  return found;
}

function client(ssid: string, label: string): HTMLElement {
  const found = within(row(ssid))
    .getAllByTestId("ssid-client")
    .find((c) => within(c).queryByText(label) !== null);
  if (!found) throw new Error(`no client ${label} on ${ssid}`);
  return found;
}

/** Classes plug-kitchen (on the IoT SSID) as an IoT device too, so a second finding exists. */
function classPlugAsIot(): void {
  mockTopologyDecisions.iotHosts.add(HOST_IDS["plug-kitchen"] as string);
}

describe("the tree of SSIDs", () => {
  it("lists the three SSIDs of the lab with their VLAN, network, client count and policy", async () => {
    await openSsids();
    expect(rows().map((r) => r.dataset.ssid)).toEqual([S.guest, S.home, S.iot]);
    expect(rows().map((r) => r.dataset.policy)).toEqual(["ignore", "track", "track"]);

    const guest = row(S.guest);
    const chip = guest.querySelector(".vlan") as HTMLElement;
    expect(chip.dataset.vid).toBe("40");
    expect(chip.textContent).toContain("DMZ");
    expect(within(guest).getByTestId("ssid-prefix").textContent).toBe("203.0.113.128/26");
    expect(within(guest).getByTestId("ssid-clients").textContent).toBe("1 client");
    expect(within(guest).getByTestId("ssid-guest").textContent).toBe("Guest");
    expect(within(guest).getByTestId("ssid-policy").textContent).toBe("Ignore");
    expect(within(guest).getByTestId("ssid-policy").getAttribute("aria-pressed")).toBe("false");

    const home = row(S.home);
    expect((home.querySelector(".vlan") as HTMLElement).dataset.vid).toBe("10");
    expect(within(home).getByTestId("ssid-prefix").textContent).toContain("192.0.2.0/24");
    expect(within(home).getByTestId("ssid-clients").textContent).toBe("1 client");
    expect(within(home).queryByTestId("ssid-guest")).toBeNull();
    expect(within(home).getByTestId("ssid-policy").textContent).toBe("Track");
    expect(within(home).getByTestId("ssid-policy").getAttribute("aria-pressed")).toBe("true");

    const iot = row(S.iot);
    expect((iot.querySelector(".vlan") as HTMLElement).dataset.vid).toBe("30");
    expect(within(iot).getByTestId("ssid-prefix").textContent).toContain("198.51.100.0/24");
    expect(within(iot).getByTestId("ssid-clients").textContent).toBe("5 clients");
    expect(within(iot).getAllByTestId("ssid-client")).toHaveLength(5);
  });

  it("shows a client with its MAC address, address, access point and radio band in words", async () => {
    await openSsids();
    const tv = client(S.home, "tv-living");
    expect(tv.dataset.mac).toBe("00:00:5e:00:53:39");
    const cells = [...tv.querySelectorAll("td")].map((td) => td.textContent);
    expect(cells[1]).toBe("00:00:5e:00:53:39");
    expect(cells[2]).toBe("192.0.2.57");
    expect(cells[3]).toBe("ap-hall");
    expect(within(tv).getByTestId("ssid-client-band").textContent).toBe("6 GHz");

    const bands = within(row(S.iot))
      .getAllByTestId("ssid-client")
      .map((c) => [c.querySelector("button")?.textContent, within(c).getByTestId("ssid-client-band").textContent]);
    expect(bands).toEqual([
      ["cam-door", "5 GHz"],
      ["plug-kitchen", "2.4 GHz"],
      ["sensor-garage", "2.4 GHz"],
      ["speaker-den", "5 GHz"],
      ["thermostat-1", "2.4 GHz"],
    ]);
    expect(within(client(S.guest, "Example Devices 00:53:d3")).getByTestId("ssid-client-band").textContent).toBe("5 GHz");
    // The access point is a column of the client row, not a level of the tree.
    expect(within(client(S.guest, "Example Devices 00:53:d3")).getByText("ap-attic")).toBeTruthy();
  });

  it("names the device on the map when its name is clicked", async () => {
    const { onShowNode } = await openSsids();
    fireEvent.click(within(client(S.home, "tv-living")).getByTestId("ssid-client-show"));
    expect(onShowNode).toHaveBeenCalledWith(T.tv);
    fireEvent.click(within(client(S.guest, "Example Devices 00:53:d3")).getByTestId("ssid-client-show"));
    expect(onShowNode).toHaveBeenLastCalledWith(T.guestClient);
  });

  it("collapses and opens an SSID", async () => {
    await openSsids();
    const toggle = within(row(S.iot)).getByTestId("ssid-toggle");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(toggle.getAttribute("aria-label")).toBe("Collapse iot.example.test");
    fireEvent.click(toggle);
    expect(within(row(S.iot)).queryAllByTestId("ssid-client")).toHaveLength(0);
    expect(within(row(S.iot)).getByTestId("ssid-toggle").getAttribute("aria-expanded")).toBe("false");
    expect(within(row(S.iot)).getByTestId("ssid-toggle").getAttribute("aria-label")).toBe("Expand iot.example.test");
    // The other SSIDs keep their clients.
    expect(within(row(S.home)).getAllByTestId("ssid-client")).toHaveLength(1);
    fireEvent.click(within(row(S.iot)).getByTestId("ssid-toggle"));
    expect(within(row(S.iot)).getAllByTestId("ssid-client")).toHaveLength(5);
  });

  it("says that no controller reports an SSID, with a way to the connectors", async () => {
    mockVlanController.present = false;
    renderSsids();
    const empty = await screen.findByTestId("ssid-empty");
    expect(empty.textContent).toContain("No network controller reports an SSID.");
    expect(within(empty).getByRole("link", { name: "Open the connectors" }).getAttribute("href")).toBe("/connectors");
    expect(rows()).toHaveLength(0);
  });

  it("shows the loading state first", async () => {
    renderSsids();
    expect(screen.getByTestId("ssid-loading").textContent).toContain("Loading the map");
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(screen.queryByTestId("ssid-loading")).toBeNull();
  });
});

describe("the findings of the WLAN rules", () => {
  it("marks the IoT host on the home WLAN with its finding, a link to move it and a way to keep it", async () => {
    await openSsids();
    const tv = client(S.home, "tv-living");
    expect(tv.dataset.findings).toBe("1");
    expect(within(tv).getByTestId("ssid-client-iot").textContent).toBe("IoT");
    expect(within(tv).getByTestId("ssid-client-finding").dataset.kind).toBe("wlan_class");
    expect(within(tv).getByTestId("ssid-client-finding").textContent).toBe("IoT device on a non-IoT WLAN");
    expect(within(row(S.home)).getByTestId("ssid-findings").textContent).toBe("1 to review");
    const move = within(tv).getByTestId("ssid-client-move");
    expect(move.textContent).toBe("Move…");
    expect(move.getAttribute("href")).toBe("/ipam/hosts/tv-living");
    expect(within(tv).getByTestId("ssid-client-keep").textContent).toBe("Keep on this WLAN");
    // Nobody else has a finding or an action.
    expect(screen.getAllByTestId("ssid-client").filter((c) => c.dataset.findings !== "0")).toEqual([tv]);
    expect(screen.getAllByTestId("ssid-client-move")).toHaveLength(1);
    expect(screen.getAllByTestId("ssid-client-keep")).toHaveLength(1);
    expect(screen.queryAllByTestId("ssid-findings")).toHaveLength(1);
  });

  it("keeps a host on its WLAN and lets the finding of that host only go", async () => {
    classPlugAsIot();
    await openSsids();
    expect(screen.getAllByTestId("ssid-client-keep")).toHaveLength(2);
    expect(client(S.iot, "plug-kitchen").dataset.findings).toBe("1");

    fireEvent.click(within(client(S.home, "tv-living")).getByTestId("ssid-client-keep"));
    await waitFor(() => expect(client(S.home, "tv-living").dataset.findings).toBe("0"));
    expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-kept").textContent).toBe("Kept on this WLAN");
    expect(within(client(S.home, "tv-living")).queryByTestId("ssid-client-keep")).toBeNull();
    expect(within(client(S.home, "tv-living")).queryByTestId("ssid-client-move")).toBeNull();
    expect(within(row(S.home)).queryByTestId("ssid-findings")).toBeNull();
    // The other host stays flagged.
    expect(client(S.iot, "plug-kitchen").dataset.findings).toBe("1");
    expect(within(client(S.iot, "plug-kitchen")).getByTestId("ssid-client-keep")).toBeTruthy();
    expect(within(row(S.iot)).getByTestId("ssid-findings").textContent).toBe("1 to review");
    // The server stored it for that host on that SSID.
    expect([...mockTopologyDecisions.exceptions.keys()]).toEqual([`${HOST_IDS["tv-living"]}|${S.home}`]);
    // And the findings list agrees.
    const open = (await api.get("/api/v1/findings", { query: { area: "topology" } })).items;
    expect(open.map((f) => f.subject.label)).toEqual(["plug-kitchen"]);
  });

  it("shows why a write failed and leaves the finding in place", async () => {
    server.use(
      http.put(
        "/api/v1/topology/ssids/:ssid/exceptions/:host",
        () =>
          HttpResponse.json(
            { code: "ipam.topology.invalid", status: 422, title: "Invalid", detail: "no", params: { field: "ssid" } },
            { status: 422, headers: PROBLEM },
          ),
        { once: true },
      ),
    );
    await openSsids();
    fireEvent.click(within(client(S.home, "tv-living")).getByTestId("ssid-client-keep"));
    const failure = await screen.findByTestId("ssid-failure");
    expect(failure.textContent).toContain("The topology decision is not valid: ssid is out of bounds.");
    expect(client(S.home, "tv-living").dataset.findings).toBe("1");
    expect((within(client(S.home, "tv-living")).getByTestId("ssid-client-keep") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("the policy of an SSID", () => {
  it("switches an SSID between track and ignore through the server", async () => {
    await openSsids();
    const guest = () => row(S.guest);
    fireEvent.click(within(guest()).getByTestId("ssid-policy"));
    await waitFor(() => expect(guest().dataset.policy).toBe("track"));
    expect(within(guest()).getByTestId("ssid-policy").textContent).toBe("Track");
    expect(within(guest()).getByTestId("ssid-policy").getAttribute("aria-pressed")).toBe("true");
    expect(mockTopologyDecisions.policies.get(S.guest)?.policy).toBe("track");

    fireEvent.click(within(guest()).getByTestId("ssid-policy"));
    await waitFor(() => expect(guest().dataset.policy).toBe("ignore"));
    expect(within(guest()).getByTestId("ssid-policy").textContent).toBe("Ignore");
    expect(mockTopologyDecisions.policies.get(S.guest)?.policy).toBe("ignore");
  });

  it("shows no findings on an ignored SSID, and brings them back when it is tracked again", async () => {
    await openSsids();
    expect(within(row(S.home)).getByTestId("ssid-findings")).toBeTruthy();

    fireEvent.click(within(row(S.home)).getByTestId("ssid-policy"));
    await waitFor(() => expect(row(S.home).dataset.policy).toBe("ignore"));
    expect(within(row(S.home)).queryByTestId("ssid-findings")).toBeNull();
    expect(client(S.home, "tv-living").dataset.findings).toBe("0");
    expect(within(client(S.home, "tv-living")).queryByTestId("ssid-client-finding")).toBeNull();
    expect(within(client(S.home, "tv-living")).queryByTestId("ssid-client-keep")).toBeNull();
    expect(screen.queryAllByTestId("ssid-client-finding")).toHaveLength(0);
    // The client is still listed, still IoT.
    expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-iot")).toBeTruthy();

    fireEvent.click(within(row(S.home)).getByTestId("ssid-policy"));
    await waitFor(() => expect(row(S.home).dataset.policy).toBe("track"));
    await waitFor(() => expect(client(S.home, "tv-living").dataset.findings).toBe("1"));
  });
});

describe("what each person may do", () => {
  it("offers a viewer no write button, only the facts", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["viewer"];
      },
    });
    await openSsids();
    expect(screen.queryAllByTestId("ssid-client-keep")).toHaveLength(0);
    const policies = screen.getAllByTestId("ssid-policy");
    expect(policies).toHaveLength(3);
    for (const chip of policies) expect(chip.tagName).toBe("SPAN");
    expect(policies.map((p) => p.textContent)).toEqual(["Ignore", "Track", "Track"]);
    // The finding is still shown, and so is the way to the host.
    expect(client(S.home, "tv-living").dataset.findings).toBe("1");
    expect(screen.queryByTestId("ssid-read-only")).toBeNull();
  });

  it("offers no write action at all when the view is read-only", async () => {
    await openSsids({ readOnly: true });
    expect(screen.getByTestId("ssid-read-only").textContent).toContain("Read-only");
    expect(screen.queryAllByTestId("ssid-client-keep")).toHaveLength(0);
    expect(screen.queryAllByTestId("ssid-client-move")).toHaveLength(0);
    for (const chip of screen.getAllByTestId("ssid-policy")) expect(chip.tagName).toBe("SPAN");
    // What is known stays visible.
    expect(client(S.home, "tv-living").dataset.findings).toBe("1");
    expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-finding")).toBeTruthy();
  });
});

describe("accessibility and language", () => {
  it("has no axe violations", async () => {
    await openSsids();
    expect(await axeViolations(screen.getByTestId("ssid-view"))).toEqual([]);
  });

  it("has no axe violations when read-only", async () => {
    await openSsids({ readOnly: true });
    expect(await axeViolations(screen.getByTestId("ssid-view"))).toEqual([]);
  });

  it("renders in Swedish", async () => {
    await setLocale("sv");
    try {
      await openSsids();
      expect(within(row(S.guest)).getByTestId("ssid-guest").textContent).toBe("Gäst");
      expect(within(row(S.guest)).getByTestId("ssid-policy").textContent).toBe("Ignorera");
      expect(within(row(S.home)).getByTestId("ssid-policy").textContent).toBe("Följ");
      expect(within(row(S.iot)).getByTestId("ssid-clients").textContent).toBe("5 klienter");
      expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-move").textContent).toBe("Flytta…");
      expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-keep").textContent).toBe("Behåll på detta WLAN");
      expect(within(client(S.home, "tv-living")).getByTestId("ssid-client-band").textContent).toBe("6 GHz");
    } finally {
      await setLocale("en");
    }
  });
});
