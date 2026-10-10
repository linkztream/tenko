import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { server } from "../api/mock/node";
import { TOPOLOGY_IDS } from "../api/mock/topology-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { NodePanel, type NodePanelProps } from "./NodePanel";

const T = TOPOLOGY_IDS;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
  server.events.removeAllListeners();
});

function handlers() {
  return {
    onSelect: vi.fn<(id: string) => void>(),
    onClose: vi.fn<() => void>(),
    onPathRouter: vi.fn<() => void>(),
    onPathStart: vi.fn<() => void>(),
    onPathShow: vi.fn<() => void>(),
    onPathClear: vi.fn<() => void>(),
  };
}

type Handlers = ReturnType<typeof handlers>;

/** Renders the panel of a device inside a router, with sensible defaults for the map's part. */
function renderPanel(id: string, overrides: Partial<NodePanelProps> = {}): Handlers & ReturnType<typeof renderRoute> {
  const calls = handlers();
  const view = renderRoute(
    () => (
      <NodePanel
        id={id}
        pathStart={undefined}
        routerReachable
        startReachable={false}
        pathShown={false}
        vlanStyle={() => undefined}
        vlanName={(vid) => (vid === 10 ? "Management" : vid === 30 ? "IoT" : undefined)}
        {...calls}
        {...overrides}
      />
    ),
    { url: `/topology/${id}`, path: "/topology/:id?" },
  );
  return { ...calls, ...view };
}

async function loaded(id: string) {
  const panel = await screen.findByTestId("node-panel");
  await screen.findByTestId("node-label");
  expect(panel.dataset.id).toBe(id);
  return panel;
}

const port = (key: string): HTMLElement => {
  const found = screen.getAllByTestId("node-port").find((p) => p.dataset.key === key);
  if (!found) throw new Error(`no port ${key}`);
  return found;
};

describe("what the panel says about a device", () => {
  it("names the device, its kind and what the sources know", async () => {
    renderPanel(T.swCore);
    const panel = await loaded(T.swCore);
    expect(panel.tagName).toBe("ASIDE");
    expect(panel.getAttribute("aria-label")).toBe("Device details");
    expect(screen.getByTestId("node-label").textContent).toBe("sw-core");
    expect(screen.getByTestId("node-kind").textContent).toBe("Switch");
    expect(screen.getByTestId("node-kind").dataset.kind).toBe("switch");
    expect(screen.getByTestId("node-model").textContent).toBe("USW-24-PoE");
    expect(screen.getByTestId("node-ips").textContent).toMatch(/^\d+\.\d+\.\d+\.\d+/);
    expect(screen.getByTestId("node-macs").textContent).toMatch(/[0-9a-f]{2}:[0-9a-f]{2}/i);
    expect(screen.getByTestId("node-sources").textContent).toBe("Intent, Network controller");
    expect(screen.getByTestId("node-last-seen").textContent).toMatch(/minute|second/);
    // VLANs show their id, with the name when the map knows it.
    const vlans = within(screen.getByTestId("node-vlans")).getAllByText(/^\d+$/).map((e) => e.textContent);
    expect(vlans).toContain("10");
    expect(screen.getByTestId("node-vlans").textContent).toContain("Management");
  });

  it("links to the host page and to the observations of a host of intent", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    expect(screen.getByTestId("node-host-link").getAttribute("href")).toBe("/ipam/hosts/sw-core");
    const view = await api.get("/api/v1/topology/nodes/{id}", { path: { id: T.swCore } });
    expect(screen.getByTestId("node-observation-link").getAttribute("href")).toBe(`/discovery/observations/${view.node.subject}`);
  });

  it("lists the addresses of the host of intent with their network and VLAN", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    const intent = screen.getByTestId("node-intent");
    expect(intent.textContent).toContain("sw-core");
    const addresses = within(intent).getAllByTestId("intent-address");
    expect(addresses.length).toBeGreaterThan(0);
    const view = await api.get("/api/v1/topology/nodes/{id}", { path: { id: T.swCore } });
    expect(addresses.map((a) => a.dataset.key)).toEqual((view.intent?.addresses ?? []).map((a) => a.ip));
    const first = addresses[0] as HTMLElement;
    expect(first.textContent).toContain(view.intent?.addresses[0]?.cidr);
    expect(first.querySelector("[data-vid]")?.getAttribute("data-vid")).toBe(String(view.intent?.addresses[0]?.vid));
  });

  it("has no host link for a device that IPAM does not know, but still the observations", async () => {
    renderPanel(T.apAttic);
    await loaded(T.apAttic);
    expect(screen.queryByTestId("node-host-link")).toBeNull();
    expect(screen.getByTestId("node-observation-link").getAttribute("href")).toBe("/discovery/observations/00:00:5e:00:53:a6");
    expect(screen.getByTestId("node-intent").textContent).toContain("This device is not a host in IPAM.");
    expect(screen.queryAllByTestId("intent-address")).toHaveLength(0);
    expect(screen.getByTestId("node-ssids").textContent).toBe("home.example.test");
    expect(screen.getByTestId("node-sources").textContent).toBe("Network controller");
  });

  it("shows the vendor of a client and leaves out what the sources do not know", async () => {
    renderPanel(T.unknown);
    await loaded(T.unknown);
    expect(screen.getByTestId("node-vendor").textContent).toBe("Example Devices");
    expect(screen.queryByTestId("node-model")).toBeNull();
    expect(screen.queryByTestId("node-os")).toBeNull();
    expect(screen.queryByTestId("node-ips")).toBeNull();
  });

  it("shows the operating system an inventory reports", async () => {
    renderPanel(T.mediaPc);
    await loaded(T.mediaPc);
    expect(screen.getByTestId("node-os").textContent).toBe("Debian 12");
    expect(screen.getByTestId("node-sources").textContent).toBe("Inventory");
  });
});

describe("ports", () => {
  it("lists the ports with their controller name, uplink, untagged VLAN, link state and what hangs on them", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    const ports = screen.getAllByTestId("node-ports")[0] as HTMLElement;
    expect(within(ports).getAllByTestId("node-port").map((p) => p.dataset.key)).toEqual(["1", "2", "3", "4", "5", "6", "7", "8"]);

    const first = port("1");
    expect(first.textContent).toContain("1 (Port 1)");
    expect(within(first).getByTestId("port-uplink").textContent).toBe("Uplink");
    expect(within(first).getByTestId("port-vlan").textContent).toContain("10");
    expect(within(first).getByTestId("port-state").textContent).toBe("Link up");
    expect(within(first).getByTestId("port-state").dataset.state).toBe("up");
    expect(within(first).getByTestId("port-count").textContent).toBe("1 connected");

    expect(within(port("2")).queryByTestId("port-uplink")).toBeNull();
    expect(within(port("8")).getByTestId("port-state").textContent).toBe("Link down");
    expect(within(port("8")).getByTestId("port-count").textContent).toBe("nothing connected");
    expect((within(port("8")).getByTestId("node-port-open") as HTMLButtonElement).disabled).toBe(true);
  });

  it("loads what hangs on a port when its button is pressed, and lists it", async () => {
    const requests: string[] = [];
    server.events.on("request:start", ({ request }) => {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/v1/topology/nodes/")) requests.push(url.pathname + url.search);
    });
    const view = renderPanel(T.swCore);
    await loaded(T.swCore);
    const open = within(port("3")).getByTestId("node-port-open") as HTMLButtonElement;
    expect(open.getAttribute("aria-expanded")).toBe("false");
    expect(open.getAttribute("aria-label")).toBe("Show what is connected to port 3");
    expect(open.textContent).toBe("Show what is connected");
    expect(screen.queryByTestId("port-neighbours")).toBeNull();

    fireEvent.click(open);
    const list = await screen.findByTestId("port-neighbours");
    expect(list.dataset.key).toBe("3");
    await waitFor(() => expect(within(list).getAllByTestId("port-neighbour")).toHaveLength(1));
    const neighbour = within(list).getByTestId("port-neighbour");
    expect(neighbour.dataset.id).toBe(T.nas);
    expect(neighbour.textContent).toContain("nas");
    expect(neighbour.textContent).toContain("Host");
    expect(neighbour.textContent).toContain("Wired");
    expect(neighbour.textContent).toContain("port 3");
    expect(neighbour.querySelector("[data-vid]")?.getAttribute("data-vid")).toBe("10");
    expect(requests).toContain(`/api/v1/topology/nodes/${T.swCore}?port=3`);
    expect(open.getAttribute("aria-expanded")).toBe("true");
    expect(open.getAttribute("aria-label")).toBe("Hide what is connected to port 3");
    expect(open.getAttribute("aria-controls")).toBe(list.id);
    // Only the opened port lists its neighbours.
    expect(screen.getAllByTestId("port-neighbours")).toHaveLength(1);

    // A neighbour of the port is a button that selects that device.
    fireEvent.click(neighbour);
    expect(view.onSelect).toHaveBeenCalledWith(T.nas);

    // Pressing the button again hides the list.
    fireEvent.click(open);
    expect(screen.queryByTestId("port-neighbours")).toBeNull();
    expect(open.getAttribute("aria-expanded")).toBe("false");
  });

  it("moves the list to another port when its button is pressed", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    fireEvent.click(within(port("3")).getByTestId("node-port-open"));
    await waitFor(() => expect(within(screen.getByTestId("port-neighbours")).getAllByTestId("port-neighbour")[0]?.dataset.id).toBe(T.nas));
    fireEvent.click(within(port("6")).getByTestId("node-port-open"));
    await waitFor(() => expect(screen.getByTestId("port-neighbours").dataset.key).toBe("6"));
    await waitFor(() => expect(within(screen.getByTestId("port-neighbours")).getAllByTestId("port-neighbour")[0]?.dataset.id).toBe(T.swDesk));
    expect(screen.getAllByTestId("port-neighbours")).toHaveLength(1);
    expect(within(screen.getByTestId("port-neighbours")).getAllByTestId("port-neighbour")[0]?.textContent).toContain("LLDP link");
  });

  it("shows the error when the port cannot be read", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    server.use(
      http.get(
        `/api/v1/topology/nodes/${T.swCore}`,
        () => HttpResponse.json({ code: "ipam.topology.unavailable", status: 503, title: "Unavailable", detail: "off", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    fireEvent.click(within(port("3")).getByTestId("node-port-open"));
    const list = await screen.findByTestId("port-neighbours");
    await waitFor(() => expect(list.textContent).toContain("The topology is not available on this server."));
  });

  it("says when a device has no ports", async () => {
    renderPanel(T.tv);
    await loaded(T.tv);
    // The TV has no ports of its own: the wireless link names none.
    expect(screen.queryAllByTestId("node-port")).toHaveLength(0);
    expect(screen.getByText("No ports are known for this device.")).toBeTruthy();
  });
});

describe("neighbours", () => {
  it("lists every neighbour with its edge kind, ports and VLAN, and selects the one that is pressed", async () => {
    const view = renderPanel(T.swDesk);
    await loaded(T.swDesk);
    const list = screen.getByTestId("node-neighbours");
    const neighbours = within(list).getAllByTestId("neighbour");
    expect(neighbours.map((n) => n.dataset.id).sort()).toEqual([T.swCore, T.apGarage, T.apAttic, T.tenko1, T.tenko2, T.tenko3, T.laptop, T.unknown].sort());
    const swCore = neighbours.find((n) => n.dataset.id === T.swCore) as HTMLElement;
    expect(swCore.textContent).toContain("sw-core");
    expect(swCore.textContent).toContain("Switch");
    expect(swCore.textContent).toContain("LLDP link");
    expect(swCore.textContent).toContain("port 1");
    expect(swCore.textContent).toContain("remote port 6");
    const tenko = neighbours.find((n) => n.dataset.id === T.tenko1) as HTMLElement;
    expect(tenko.textContent).toContain("Wired");
    expect(tenko.querySelector("[data-vid]")?.getAttribute("data-vid")).toBe("20");
    expect(tenko.dataset.edge).toMatch(/^e-[0-9a-f]{12}$/);

    fireEvent.click(tenko);
    expect(view.onSelect).toHaveBeenCalledWith(T.tenko1);
  });

  it("names the wireless network of a wireless link", async () => {
    renderPanel(T.apHall);
    await loaded(T.apHall);
    const plug = within(screen.getByTestId("node-neighbours")).getAllByTestId("neighbour").find((n) => n.dataset.id === T.plug) as HTMLElement;
    expect(plug.textContent).toContain("Wireless");
    expect(plug.textContent).toContain("network iot.example.test");
    expect(plug.querySelector("[data-vid]")?.getAttribute("data-vid")).toBe("30");
  });
});

describe("path actions", () => {
  it("asks for the path to the nearest router", async () => {
    const view = renderPanel(T.tenko1);
    await loaded(T.tenko1);
    const button = screen.getByTestId("node-path-router") as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    expect(screen.queryByTestId("node-path-router-reason")).toBeNull();
    fireEvent.click(button);
    expect(view.onPathRouter).toHaveBeenCalledTimes(1);
    // Nothing is highlighted and no start is remembered: no clear button, no show button.
    expect(screen.queryByTestId("node-path-clear")).toBeNull();
    expect(screen.queryByTestId("node-path-show")).toBeNull();
  });

  it("disables the path to a router with its reason when none is reachable", async () => {
    renderPanel(T.tenko1, { routerReachable: false });
    await loaded(T.tenko1);
    expect((screen.getByTestId("node-path-router") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("node-path-router-reason").textContent).toBe("No router is reachable from this device in the current view.");
  });

  it("remembers the device as the start of a path", async () => {
    const view = renderPanel(T.printer);
    await loaded(T.printer);
    const from = screen.getByTestId("node-path-from");
    expect(from.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(from);
    expect(view.onPathStart).toHaveBeenCalledTimes(1);
  });

  it("offers the path from a remembered start to this device, and clearing it", async () => {
    const view = renderPanel(T.tenko1, { pathStart: { id: T.printer, label: "printer-1" }, startReachable: true });
    await loaded(T.tenko1);
    expect(screen.getByTestId("node-path-start").textContent).toBe("Path start: printer-1");
    const show = screen.getByTestId("node-path-show") as HTMLButtonElement;
    expect(show.disabled).toBe(false);
    fireEvent.click(show);
    expect(view.onPathShow).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByTestId("node-path-clear"));
    expect(view.onPathClear).toHaveBeenCalledTimes(1);
  });

  it("disables the path to the start with its reason when the view does not join them", async () => {
    renderPanel(T.tenko1, { pathStart: { id: T.printer, label: "printer-1" }, startReachable: false });
    await loaded(T.tenko1);
    expect((screen.getByTestId("node-path-show") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("node-path-show-reason").textContent).toBe("No path joins the start and this device in the current view.");
  });

  it("offers neither the path to the start nor its reason on the start itself", async () => {
    renderPanel(T.printer, { pathStart: { id: T.printer, label: "printer-1" } });
    await loaded(T.printer);
    expect(screen.queryByTestId("node-path-show")).toBeNull();
    expect(screen.getByTestId("node-path-from").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("node-path-start").textContent).toBe("This device is the start of the path.");
    expect(screen.getByTestId("node-path-clear")).toBeTruthy();
  });

  it("offers to clear a path that is highlighted", async () => {
    const view = renderPanel(T.tenko1, { pathShown: true });
    await loaded(T.tenko1);
    fireEvent.click(screen.getByTestId("node-path-clear"));
    expect(view.onPathClear).toHaveBeenCalledTimes(1);
  });

  it("does not offer a path to a router from a router", async () => {
    renderPanel(T.gateway);
    await loaded(T.gateway);
    expect((screen.getByTestId("node-path-router") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("node-path-router-reason").textContent).toBe("This device is a router.");
  });
});

describe("closing and failing", () => {
  it("closes with the close button and with Escape", async () => {
    const view = renderPanel(T.swCore);
    const panel = await loaded(T.swCore);
    fireEvent.click(screen.getByTestId("node-panel-close"));
    expect(view.onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(panel, { key: "Escape" });
    expect(view.onClose).toHaveBeenCalledTimes(2);
  });

  it("says that the graph no longer has the device and offers a way back", async () => {
    const view = renderPanel("m-00005e00dead");
    const note = await screen.findByTestId("node-not-found");
    expect(note.textContent).toBe("This device is no longer in the topology.");
    expect(screen.queryByTestId("node-label")).toBeNull();
    expect(screen.queryByText("Try again")).toBeNull();
    fireEvent.click(screen.getByTestId("node-panel-back"));
    expect(view.onClose).toHaveBeenCalledTimes(1);
  });

  it("shows another error with a way back and a retry", async () => {
    server.use(
      http.get(
        `/api/v1/topology/nodes/${T.swCore}`,
        () => HttpResponse.json({ code: "ipam.topology.unavailable", status: 503, title: "Unavailable", detail: "off", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
        { once: true },
      ),
    );
    const view = renderPanel(T.swCore);
    const panel = await screen.findByTestId("node-panel");
    await waitFor(() => expect(panel.textContent).toContain("The topology is not available on this server."));
    expect(screen.queryByTestId("node-not-found")).toBeNull();
    expect(screen.getByTestId("node-panel-back")).toBeTruthy();
    fireEvent.click(within(panel).getByRole("button", { name: "Try again" }));
    await screen.findByTestId("node-label");
    expect(screen.getByTestId("node-label").textContent).toBe("sw-core");
    expect(view.onClose).not.toHaveBeenCalled();
  });

  it("shows a loading state first", async () => {
    renderPanel(T.swCore);
    const panel = await screen.findByTestId("node-panel");
    expect(panel.textContent).toContain("Loading");
    await screen.findByTestId("node-label");
    expect(panel.textContent).not.toContain("Loading");
  });
});

describe("accessibility", () => {
  it("has no axe violations", async () => {
    renderPanel(T.swCore);
    await loaded(T.swCore);
    fireEvent.click(within(port("3")).getByTestId("node-port-open"));
    await waitFor(() => expect(screen.getAllByTestId("port-neighbour")).toHaveLength(1));
    expect(await axeViolations(screen.getByTestId("node-panel"))).toEqual([]);
  });

  it("has no axe violations for a device without intent and with a path started", async () => {
    renderPanel(T.apAttic, { pathStart: { id: T.printer, label: "printer-1" }, startReachable: true, pathShown: true });
    await loaded(T.apAttic);
    expect(await axeViolations(screen.getByTestId("node-panel"))).toEqual([]);
  });
});
