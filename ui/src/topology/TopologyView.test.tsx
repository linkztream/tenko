import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { server } from "../api/mock/node";
import { mockVlanController, TOPOLOGY_COUNTS, TOPOLOGY_IDS, TOPOLOGY_SSIDS, topologyState } from "../api/mock/topology-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { db, signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import TopologyView from "./TopologyView";

type Graph = components["schemas"]["TopologyGraph"];

const T = TOPOLOGY_IDS;
const SSID = TOPOLOGY_SSIDS;
const PROBLEM = { "content-type": "application/problem+json" };

let stopBridge: (() => void) | undefined;

/** The browser's "Endpoints" switch of the map: these scenarios draw every endpoint. */
const ENDPOINTS_KEY = "tenko-topology-endpoints";

beforeEach(async () => {
  await signInAlex();
  localStorage.setItem(ENDPOINTS_KEY, "all");
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  vi.useRealTimers();
  vi.unstubAllGlobals();
  setSessionForTest(null);
});

function renderMap(url = "/topology") {
  return renderRoute(TopologyView, { url, path: "/topology/:id?" });
}

const nodes = (): HTMLElement[] => screen.queryAllByTestId("topology-node");
const groups = (): HTMLElement[] => screen.queryAllByTestId("topology-group");
const edges = (): HTMLElement[] => screen.queryAllByTestId("topology-edge");
const nodeIds = (): string[] => nodes().map((n) => n.dataset.id as string).sort();

function node(id: string): HTMLElement {
  const found = nodes().find((n) => n.dataset.id === id);
  if (!found) throw new Error(`no device ${id} on the map`);
  return found;
}

/** The ids of the elements that carry `data-path="true"`. */
const pathNodeIds = (): string[] => [...nodes(), ...groups()].filter((n) => n.dataset.path === "true").map((n) => n.dataset.id as string).sort();
const pathEdgeCount = (): number => edges().filter((e) => e.dataset.path === "true").length;

/** Renders the map and waits until `count` devices are drawn. */
async function openMap(url = "/topology", count: number = TOPOLOGY_COUNTS.nodes) {
  const view = renderMap(url);
  await waitFor(() => expect(nodes()).toHaveLength(count));
  return view;
}

const transform = (): string => screen.getByTestId("topology-drawing").getAttribute("transform") ?? "";
const scaleOf = (): number => Number(/scale\(([-\d.]+)\)/.exec(transform())?.[1]);
const translateOf = (): [number, number] => {
  const m = /translate\(([-\d.]+) ([-\d.]+)\)/.exec(transform());
  return [Number(m?.[1]), Number(m?.[2])];
};

const sorted = (list: readonly string[]): string[] => [...list].sort();

async function graphOf(query: Record<string, string> = {}): Promise<Graph> {
  return api.get("/api/v1/topology", { query });
}

/** A copy of the seeded graph with changes, answered instead of the mock's own answer. */
async function answer(change: (graph: Graph) => void): Promise<void> {
  const graph = structuredClone(await graphOf());
  change(graph);
  server.use(http.get("/api/v1/topology", () => HttpResponse.json(graph)));
}

/** Adds `count` wired clients to a switch of the mock lab; returns their ids. */
function addClients(parent: string, count: number): string[] {
  const state = topologyState();
  const ids: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const n = String(i).padStart(2, "0");
    const mac = `00:00:5e:00:ff:${n}`;
    const id = `m-00005e00ff${n}`;
    state.nodes.push({
      id,
      kind: "host",
      label: `extra-${n}`,
      macs: [mac],
      subject: mac,
      vlans: [10],
      sources: ["network_controller:test"],
    });
    state.edges.push({ id: `e-0000000000${n}`, kind: "wired", a: parent, a_port: String(20 + i), b: id, vlan: 10, sources: ["network_controller:test"] });
    ids.push(id);
  }
  return ids;
}

describe("the map", () => {
  it("draws every device and every link of the lab with their kinds", async () => {
    await openMap();
    expect(screen.getByTestId("page-topology")).toBeTruthy();
    expect(screen.getByTestId("topology-map").getAttribute("role")).toBe("group");
    expect(screen.getByTestId("topology-map").getAttribute("aria-label")).toBe("Network map");
    expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes);
    expect(edges()).toHaveLength(TOPOLOGY_COUNTS.edges);
    expect(groups()).toHaveLength(0);

    const count = (items: HTMLElement[]) => {
      const out: Record<string, number> = {};
      for (const item of items) out[item.dataset.kind as string] = (out[item.dataset.kind as string] ?? 0) + 1;
      return out;
    };
    expect(count(nodes())).toEqual({ access_point: 3, container: 1, host: 15, hypervisor: 1, router: 1, switch: 2, vm: 2 });
    expect(count(edges())).toEqual({ lldp: 1, uplink: 4, vm_host: 3, wired: 9, wireless: 7 });

    // Every device has a shape, a name with its kind in words, a visible label and a tooltip.
    const gateway = node(T.gateway);
    expect(gateway.getAttribute("role")).toBe("button");
    expect(gateway.getAttribute("aria-label")).toBe("gw, Router");
    expect(gateway.querySelector("path.shape")?.getAttribute("d")).toBeTruthy();
    expect(gateway.querySelector("text.label")?.textContent).toBe("gw");
    expect(gateway.querySelector("title")?.textContent).toBe("gw");
    expect(node(T.apHall).getAttribute("aria-label")).toBe("ap-hall, Access point");
    expect(node(T.pve1).getAttribute("aria-label")).toBe("pve1, Hypervisor");
    expect(node(T.mediaPc).getAttribute("aria-label")).toBe("media-pc, Virtual machine");
    expect(node(T.dnsCt).getAttribute("aria-label")).toBe("dns-ct, Container");
    expect(node(T.nas).getAttribute("aria-label")).toBe("nas, Host");
    // The shapes tell the kinds apart.
    const shapes = new Set(["router", "switch", "access_point", "hypervisor", "vm", "container", "host"].map((kind) => {
      const sample = nodes().find((n) => n.dataset.kind === kind);
      return sample?.querySelector("path.shape")?.getAttribute("d");
    }));
    expect(shapes.size).toBe(7);

    // Line styles by kind are classes; every link joins two drawn devices.
    const classes = Object.fromEntries(edges().map((e) => [e.dataset.kind, e.getAttribute("class")]));
    for (const kind of ["wired", "wireless", "lldp", "uplink", "vm_host"]) expect(classes[kind]).toContain(`edge-${kind}`);
    for (const edge of edges()) expect(edge.tagName.toLowerCase()).toBe("line");

    // Edges are drawn first, the devices on top.
    const drawing = screen.getByTestId("topology-drawing");
    expect(drawing.firstElementChild?.classList.contains("topology-edges")).toBe(true);
    expect(drawing.lastElementChild?.classList.contains("topology-nodes")).toBe(true);
  });

  it("says how much of the graph is shown and how the controller read went", async () => {
    await openMap();
    expect(screen.getByTestId("topology-summary").textContent).toBe(`Showing ${TOPOLOGY_COUNTS.nodes} of ${TOPOLOGY_COUNTS.nodes} devices and ${TOPOLOGY_COUNTS.edges} of ${TOPOLOGY_COUNTS.edges} links`);
    expect(screen.queryByTestId("topology-truncated")).toBeNull();
    const controllers = screen.getAllByTestId("topology-controller");
    expect(controllers).toHaveLength(1);
    expect(controllers[0]?.dataset.state).toBe("ok");
    expect(controllers[0]?.textContent).toContain("unifi.example.test");
    expect(controllers[0]?.textContent).toContain("6 devices read");
  });

  it("lists the networks the controllers report with VLAN, subnet, DHCP and management", async () => {
    await openMap();
    const block = screen.getByTestId("topology-networks");
    expect(block.querySelector("summary")?.textContent).toBe("2 networks from the network controllers");
    const rows = within(block).getAllByTestId("controller-network");
    expect(rows.map((r) => [r.dataset.key, r.dataset.vlan])).toEqual([
      ["net-mgmt", "10"],
      ["net-iot", "30"],
    ]);
    expect(rows[0]?.textContent).toContain("Management");
    expect(within(rows[0] as HTMLElement).getByTestId("network-dhcp").dataset.dhcp).toBe("server");
    expect(within(rows[1] as HTMLElement).getByTestId("network-dhcp").textContent).toBe("DHCP relay");
  });

  it("colors the links of clients with the VLAN and keeps the VLAN id as text in the legend", async () => {
    await openMap();
    const graph = await graphOf();
    const withVlan = edges().filter((e) => e.dataset.vlan !== undefined);
    // Wired and wireless client links carry a VLAN; uplinks, LLDP and virtual placement do not.
    expect(withVlan).toHaveLength(graph.edges.filter((e) => e.vlan != null).length);
    for (const edge of withVlan) {
      expect(["wired", "wireless"]).toContain(edge.dataset.kind);
      expect(edge.classList.contains("has-vlan")).toBe(true);
      expect((edge as unknown as SVGElement).style.getPropertyValue("--vlan")).toMatch(/^#[0-9A-F]{6}$/);
    }
    const colorOf = (vid: number) => (withVlan.find((e) => e.dataset.vlan === String(vid)) as unknown as SVGElement).style.getPropertyValue("--vlan");
    expect(new Set([10, 20, 30].map(colorOf)).size).toBe(3);

    const legend = screen.getByTestId("topology-legend");
    const vids = within(legend).getAllByTestId("legend-vlan").map((li) => li.dataset.vid);
    expect(vids).toEqual(graph.summary.vlans.map((v) => String(v.vid)));
    expect(within(legend).getAllByTestId("legend-vlan")[0]?.textContent).toMatch(/^10\s*\S/);
    // The edge kinds in view come with a line sample and a word, the device kinds with a shape and a word.
    expect(within(legend).getAllByTestId("legend-edge").map((li) => li.dataset.kind)).toEqual([
      "uplink",
      "wired",
      "wireless",
      "lldp",
      "vm_host",
      "inferred",
    ]);
    expect(within(legend).getAllByTestId("legend-edge")[0]?.textContent).toBe("Uplink");
    expect(within(legend).getAllByTestId("legend-kind").map((li) => li.dataset.kind)).toEqual([
      "router",
      "switch",
      "access_point",
      "hypervisor",
      "vm",
      "container",
      "host",
    ]);
  });

  it("colors only the VLAN of the filter when 150 or more VLANs are in view", async () => {
    await answer((graph) => {
      for (let vid = 100; vid < 300; vid += 1) graph.summary.vlans.push({ vid, nodes: 1 });
      graph.summary.vlans.sort((a, b) => a.vid - b.vid);
    });
    await openMap("/topology?vlan=30");
    expect(edges().filter((e) => e.dataset.vlan !== undefined && e.dataset.vlan !== "30")).toHaveLength(0);
    expect(edges().filter((e) => e.dataset.vlan === "30").length).toBeGreaterThan(0);
    expect(edges().filter((e) => e.dataset.kind === "wired" && e.dataset.vlan === undefined).length).toBeGreaterThan(0);
    const legend = screen.getByTestId("topology-legend");
    expect(within(legend).getAllByTestId("legend-vlan").map((li) => li.dataset.vid)).toEqual(["30"]);
    expect(within(legend).getByTestId("legend-vlans-neutral").textContent).toContain("204 VLANs are in view");
  });

  it("opens in the selected language", async () => {
    const { setLocale } = await import("../i18n");
    await setLocale("sv");
    try {
      await openMap();
      expect(screen.getByTestId("topology-summary").textContent).toBe(`Visar ${TOPOLOGY_COUNTS.nodes} av ${TOPOLOGY_COUNTS.nodes} enheter och ${TOPOLOGY_COUNTS.edges} av ${TOPOLOGY_COUNTS.edges} länkar`);
      expect(node(T.gateway).getAttribute("aria-label")).toBe("gw, Router");
      expect(node(T.apHall).getAttribute("aria-label")).toBe("ap-hall, Accesspunkt");
      expect(screen.getByTestId("topology-map").getAttribute("aria-label")).toBe("Nätverkskarta");
    } finally {
      await setLocale("en");
    }
  });
});

describe("the filters", () => {
  it("narrows the map to a VLAN from the select and keeps it in the URL", async () => {
    const view = await openMap();
    const select = screen.getByTestId("filter-vlan") as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toContain("30");
    expect(select.value).toBe("");

    fireEvent.change(select, { target: { value: "30" } });
    const expected = (await graphOf({ vlan: "30" })).nodes.map((n) => n.id);
    await waitFor(() => expect(nodeIds()).toEqual(sorted(expected)));
    expect(nodes().length).toBeLessThan(TOPOLOGY_COUNTS.nodes);
    expect(view.location()).toBe("/topology?vlan=30");
    expect(screen.getByTestId("topology-summary").textContent).toContain(`Showing ${expected.length} of ${TOPOLOGY_COUNTS.nodes} devices`);
    expect((screen.getByTestId("filter-vlan") as HTMLSelectElement).value).toBe("30");

    fireEvent.change(screen.getByTestId("filter-vlan"), { target: { value: "" } });
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(view.location()).toBe("/topology");
  });

  it("starts from the VLAN of the URL", async () => {
    const expected = (await graphOf({ vlan: "30" })).nodes.map((n) => n.id);
    await openMap("/topology?vlan=30", expected.length);
    expect(nodeIds()).toEqual(sorted(expected));
    expect((screen.getByTestId("filter-vlan") as HTMLSelectElement).value).toBe("30");
    // The thermostat is on the IoT network, the NAS is not.
    expect(nodeIds()).toContain(T.thermostat);
    expect(nodeIds()).not.toContain(T.nas);
  });

  it("filters by kind with toggles that keep the URL up to date", async () => {
    const view = await openMap();
    const router = screen.getByTestId("filter-kind-router");
    expect(router.getAttribute("aria-pressed")).toBe("false");

    fireEvent.click(router);
    await waitFor(() => expect(nodes()).toHaveLength(1));
    expect(nodes()[0]?.dataset.id).toBe(T.gateway);
    expect(edges()).toHaveLength(0);
    expect(screen.getByTestId("filter-kind-router").getAttribute("aria-pressed")).toBe("true");
    expect(view.location()).toBe("/topology?kind=router");

    // A second kind adds to the first.
    fireEvent.click(screen.getByTestId("filter-kind-switch"));
    await waitFor(() => expect(nodes()).toHaveLength(3));
    expect(view.location()).toBe("/topology?kind=router%2Cswitch");
    expect(edges().map((e) => e.dataset.kind).sort()).toEqual(["lldp", "uplink"]);

    fireEvent.click(screen.getByTestId("filter-kind-router"));
    await waitFor(() => expect(nodes()).toHaveLength(2));
    expect(view.location()).toBe("/topology?kind=switch");
    fireEvent.click(screen.getByTestId("filter-kind-switch"));
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(view.location()).toBe("/topology");
  });

  it("takes the kinds from the URL and ignores values it does not know", async () => {
    await openMap("/topology?kind=access_point,toaster", 3);
    expect(nodeIds()).toEqual(sorted([T.apHall, T.apGarage, T.apAttic]));
    expect(screen.getByTestId("filter-kind-access_point").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("filter-kind-host").getAttribute("aria-pressed")).toBe("false");
  });

  it("searches after a short pause in typing", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const view = await openMap();
    const input = screen.getByTestId("filter-input") as HTMLInputElement;
    expect(screen.getByTestId("filterbar")).toBeTruthy();

    fireEvent.input(input, { target: { value: "thermostat" } });
    vi.advanceTimersByTime(299);
    // Not yet: the field waits for the typing to pause.
    expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes);
    expect(view.location()).toBe("/topology");
    vi.advanceTimersByTime(1);
    await waitFor(() => expect(view.location()).toBe("/topology?q=thermostat"));

    const expected = (await graphOf({ q: "thermostat" })).nodes.map((n) => n.id);
    await waitFor(() => expect(nodeIds()).toEqual(sorted(expected)));
    expect(nodeIds()).toContain(T.thermostat);
    expect(nodes().length).toBeLessThan(TOPOLOGY_COUNTS.nodes);

    // Escape clears the field and the filter.
    fireEvent.keyDown(screen.getByTestId("filter-input"), { key: "Escape" });
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("");
    vi.advanceTimersByTime(300);
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(view.location()).toBe("/topology");
  });

  it("starts from the text of the URL and shows it in the field", async () => {
    const expected = (await graphOf({ q: "iot.example.test" })).nodes.map((n) => n.id);
    await openMap("/topology?q=iot.example.test", expected.length);
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("iot.example.test");
    expect(nodeIds()).toEqual(sorted(expected));
  });

  it("offers the sites of IPAM and sends the chosen one", async () => {
    const sites = (await api.get("/api/v1/sites")).items;
    expect(sites.length).toBeGreaterThan(0);
    const site = sites[0] as (typeof sites)[number];
    const view = await openMap();
    const select = screen.getByTestId("filter-site") as HTMLSelectElement;
    await waitFor(() => expect([...select.options].map((o) => o.value)).toContain(site.id));
    expect(select.options[0]?.textContent).toBe("All sites");
    const seen: string[] = [];
    server.events.on("request:start", ({ request }) => {
      if (new URL(request.url).pathname === "/api/v1/topology") seen.push(new URL(request.url).search);
    });
    fireEvent.change(select, { target: { value: site.id } });
    await waitFor(() => expect(view.location()).toBe(`/topology?site=${site.id}`));
    await waitFor(() => expect(seen).toContain(`?site=${site.id}`));
    server.events.removeAllListeners();
  });

  it("clears every filter at once", async () => {
    const view = await openMap("/topology?vlan=30&kind=host&q=thermostat", 1);
    expect(nodeIds()).toEqual([T.thermostat]);
    fireEvent.click(screen.getByTestId("filter-clear"));
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(view.location()).toBe("/topology");
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("");
    expect(screen.queryByTestId("filter-clear")).toBeNull();
  });
});

describe("groups", () => {
  it("shows the clients of a switch with many leaves as one group that opens on Enter", async () => {
    const extra = addClients(T.swDesk, 10);
    await openMap("/topology", TOPOLOGY_COUNTS.nodes + extra.length - 15);
    const group = screen.getByTestId("topology-group");
    expect(group.dataset.id).toBe(`group:${T.swDesk}`);
    expect(group.dataset.count).toBe("15");
    expect(group.textContent).toBe("15 devices");
    expect(group.getAttribute("role")).toBe("button");
    expect(group.getAttribute("aria-label")).toBe("15 hidden devices, open the group");
    // The hidden clients are not drawn; the number of elements stays near the number of network devices.
    expect(nodeIds()).not.toContain(extra[0]);
    expect(nodeIds()).not.toContain(T.tenko1);
    expect(edges().length).toBeLessThan(TOPOLOGY_COUNTS.edges);
    expect(screen.queryByTestId("topology-groups-close")).toBeNull();

    group.focus();
    fireEvent.keyDown(group, { key: "Enter" });
    await waitFor(() => expect(groups()).toHaveLength(0));
    expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes + extra.length);
    expect(nodeIds()).toContain(extra[0]);
    expect(nodeIds()).toContain(T.tenko1);
    // The focus moves on to the first device of the opened group.
    expect(document.activeElement).toBe(node([T.laptop, T.tenko1, T.tenko2, T.tenko3, T.unknown, ...extra].sort()[0] as string));

    // Close all groups.
    fireEvent.click(screen.getByTestId("topology-groups-close"));
    await waitFor(() => expect(groups()).toHaveLength(1));
    expect(screen.queryByTestId("topology-groups-close")).toBeNull();
  });

  it("opens on Space and on click", async () => {
    addClients(T.swDesk, 10);
    await openMap("/topology", TOPOLOGY_COUNTS.nodes + 10 - 15);
    fireEvent.keyDown(screen.getByTestId("topology-group"), { key: " " });
    await waitFor(() => expect(groups()).toHaveLength(0));
    fireEvent.click(screen.getByTestId("topology-groups-close"));
    await waitFor(() => expect(groups()).toHaveLength(1));
    fireEvent.click(screen.getByTestId("topology-group"));
    await waitFor(() => expect(groups()).toHaveLength(0));
  });

  it("opens the group of a device that a link names", async () => {
    const extra = addClients(T.swDesk, 10);
    await openMap(`/topology/${extra[3]}`, TOPOLOGY_COUNTS.nodes + 10);
    expect(groups()).toHaveLength(0);
    expect(node(extra[3] as string).dataset.selected).toBe("true");
    expect((await screen.findByTestId("node-panel")).dataset.id).toBe(extra[3]);
  });
});

describe("selecting a device", () => {
  it("opens the panel at /topology/<id> when the device is clicked, and keeps the filters", async () => {
    const view = await openMap("/topology?kind=host,switch,router", 18);
    fireEvent.click(node(T.swCore));
    await waitFor(() => expect(view.location()).toBe(`/topology/${T.swCore}?kind=host,switch,router`));
    const panel = await screen.findByTestId("node-panel");
    expect(panel.dataset.id).toBe(T.swCore);
    expect(await screen.findByTestId("node-label")).toBeTruthy();
    expect(screen.getByTestId("node-label").textContent).toBe("sw-core");
    expect(node(T.swCore).dataset.selected).toBe("true");
    expect(node(T.swCore).getAttribute("aria-current")).toBe("true");
    expect(nodes().filter((n) => n.dataset.selected === "true")).toHaveLength(1);
  });

  it("opens the panel when Enter is pressed on a device", async () => {
    const view = await openMap();
    const target = node(T.printer);
    target.focus();
    fireEvent.keyDown(target, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/topology/${T.printer}`));
    expect((await screen.findByTestId("node-panel")).dataset.id).toBe(T.printer);
  });

  it("opens the panel when a device is named in the URL", async () => {
    await openMap(`/topology/${T.apHall}`);
    expect((await screen.findByTestId("node-panel")).dataset.id).toBe(T.apHall);
    expect(node(T.apHall).dataset.selected).toBe("true");
  });

  it("closes the panel on Escape and keeps the filters", async () => {
    const view = await openMap(`/topology/${T.nas}?vlan=10`, (await graphOf({ vlan: "10" })).nodes.length);
    await screen.findByTestId("node-panel");
    fireEvent.keyDown(node(T.nas), { key: "Escape" });
    await waitFor(() => expect(view.location()).toBe("/topology?vlan=10"));
    expect(screen.queryByTestId("node-panel")).toBeNull();
    expect(nodes().filter((n) => n.dataset.selected === "true")).toHaveLength(0);
  });

  it("closes the panel with its close button", async () => {
    const view = await openMap(`/topology/${T.nas}`);
    await screen.findByTestId("node-label");
    fireEvent.click(screen.getByTestId("node-panel-close"));
    await waitFor(() => expect(view.location()).toBe("/topology"));
    expect(screen.queryByTestId("node-panel")).toBeNull();
  });

  it("shows that the graph no longer has the device, with a way back", async () => {
    const view = await openMap("/topology/m-00005e00dead");
    const note = await screen.findByTestId("node-not-found");
    expect(note.textContent).toContain("This device is no longer in the topology.");
    fireEvent.click(screen.getByTestId("node-panel-back"));
    await waitFor(() => expect(view.location()).toBe("/topology"));
  });
});

describe("paths", () => {
  it("highlights the way to the nearest router", async () => {
    await openMap(`/topology/${T.tenko1}`);
    const button = (await screen.findByTestId("node-path-router")) as HTMLButtonElement;
    await screen.findByTestId("node-label");
    expect(button.disabled).toBe(false);
    expect(pathNodeIds()).toEqual([]);

    fireEvent.click(button);
    await waitFor(() => expect(pathNodeIds()).toEqual(sorted([T.tenko1, T.swDesk, T.swCore, T.gateway])));
    expect(pathEdgeCount()).toBe(3);
    // Only the edges of the path are marked; the others stay as they are.
    expect(edges().filter((e) => e.dataset.path === "true").map((e) => e.dataset.kind).sort()).toEqual(["lldp", "uplink", "wired"]);
    expect(screen.getByTestId("topology-drawing").classList.contains("has-path")).toBe(true);
    expect(node(T.tenko1).classList.contains("on-path")).toBe(true);

    fireEvent.click(screen.getByTestId("node-path-clear"));
    await waitFor(() => expect(pathNodeIds()).toEqual([]));
    expect(pathEdgeCount()).toBe(0);
    expect(screen.getByTestId("topology-drawing").classList.contains("has-path")).toBe(false);
  });

  it("drops the highlighted path when another device is selected", async () => {
    await openMap(`/topology/${T.tenko1}`);
    fireEvent.click(await screen.findByTestId("node-path-router"));
    await waitFor(() => expect(pathNodeIds()).toHaveLength(4));
    fireEvent.click(node(T.printer));
    await waitFor(() => expect(pathNodeIds()).toEqual([]));
  });

  it("highlights the way between two chosen devices", async () => {
    await openMap(`/topology/${T.printer}`);
    expect(screen.queryByTestId("node-path-show")).toBeNull();
    fireEvent.click(await screen.findByTestId("node-path-from"));
    expect(node(T.printer).dataset.pathStart).toBe("true");
    expect(screen.getByTestId("node-path-from").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("node-path-start").textContent).toBe("This device is the start of the path.");
    // The start is remembered; with the same device selected there is nothing to show.
    expect(screen.queryByTestId("node-path-show")).toBeNull();

    fireEvent.click(node(T.tenko1));
    await waitFor(() => expect((screen.getByTestId("node-panel") as HTMLElement).dataset.id).toBe(T.tenko1));
    expect((await screen.findByTestId("node-path-start")).textContent).toBe("Path start: printer-1");
    const show = (await screen.findByTestId("node-path-show")) as HTMLButtonElement;
    expect(show.disabled).toBe(false);
    fireEvent.click(show);
    await waitFor(() => expect(pathNodeIds()).toEqual(sorted([T.printer, T.swCore, T.swDesk, T.tenko1])));
    expect(pathEdgeCount()).toBe(3);
    expect(node(T.printer).dataset.pathStart).toBe("true");

    fireEvent.click(screen.getByTestId("node-path-clear"));
    await waitFor(() => expect(pathNodeIds()).toEqual([]));
    expect(nodes().filter((n) => n.dataset.pathStart === "true")).toHaveLength(0);
    expect(screen.queryByTestId("node-path-show")).toBeNull();
    expect(screen.queryByTestId("node-path-clear")).toBeNull();
  });

  it("disables the path to a router with its reason when no router is in view", async () => {
    await openMap(`/topology/${T.nas}?kind=host`, 15);
    const button = (await screen.findByTestId("node-path-router")) as HTMLButtonElement;
    await screen.findByTestId("node-label");
    expect(button.disabled).toBe(true);
    expect(screen.getByTestId("node-path-router-reason").textContent).toBe("No router is reachable from this device in the current view.");
    expect(button.getAttribute("aria-describedby")).toBe(screen.getByTestId("node-path-router-reason").id);
  });

  it("says that a router needs no path to a router", async () => {
    await openMap(`/topology/${T.gateway}`);
    await screen.findByTestId("node-label");
    expect((screen.getByTestId("node-path-router") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("node-path-router-reason").textContent).toBe("This device is a router.");
  });

  it("marks the group when the path ends in a hidden device", async () => {
    const extra = addClients(T.swDesk, 10);
    const view = await openMap(`/topology/${extra[0]}`, TOPOLOGY_COUNTS.nodes + 10);
    fireEvent.click(await screen.findByTestId("node-path-router"));
    await waitFor(() => expect(pathNodeIds()).toEqual(sorted([extra[0] as string, T.swDesk, T.swCore, T.gateway])));
    expect(view.location()).toBe(`/topology/${extra[0]}`);
    // Close the groups: the selected device is hidden again, but its group opens again on a new selection only.
    fireEvent.click(screen.getByTestId("topology-groups-close"));
    await waitFor(() => expect(groups()).toHaveLength(1));
    expect(groups()[0]?.dataset.path).toBe("true");
    expect(pathNodeIds()).toEqual(sorted([`group:${T.swDesk}`, T.swDesk, T.swCore, T.gateway]));
    expect(pathEdgeCount()).toBe(3);
  });
});

describe("the keyboard", () => {
  const tabStops = (): HTMLElement[] => [...nodes(), ...groups()].filter((n) => n.getAttribute("tabindex") === "0");

  it("keeps exactly one device in the tab order, the first router at the start", async () => {
    await openMap();
    expect(tabStops()).toHaveLength(1);
    expect(tabStops()[0]?.dataset.id).toBe(T.gateway);
    for (const n of nodes()) if (n.dataset.id !== T.gateway) expect(n.getAttribute("tabindex")).toBe("-1");
  });

  it("starts at the selected device", async () => {
    await openMap(`/topology/${T.printer}`);
    expect(tabStops()).toHaveLength(1);
    expect(tabStops()[0]?.dataset.id).toBe(T.printer);
  });

  it("starts at the first device when there is no router", async () => {
    await openMap("/topology?kind=switch,host", 17);
    expect(tabStops()).toHaveLength(1);
    expect(tabStops()[0]?.dataset.id).toBe(nodeIds()[0]);
  });

  it("moves to the nearest device with the arrow keys and moves the tab stop with it", async () => {
    await openMap();
    const gateway = node(T.gateway);
    gateway.focus();
    // The switches hang below the router.
    fireEvent.keyDown(gateway, { key: "ArrowDown" });
    const first = document.activeElement as HTMLElement;
    expect(first.dataset.testid).toBe("topology-node");
    expect(first.dataset.id).toBe(T.swCore);
    expect(tabStops()).toHaveLength(1);
    expect(tabStops()[0]).toBe(first);

    // And back up again.
    fireEvent.keyDown(first, { key: "ArrowUp" });
    expect((document.activeElement as HTMLElement).dataset.id).toBe(T.gateway);
    expect(tabStops()[0]?.dataset.id).toBe(T.gateway);

    // Nothing above the router: the focus stays.
    fireEvent.keyDown(node(T.gateway), { key: "ArrowUp" });
    expect((document.activeElement as HTMLElement).dataset.id).toBe(T.gateway);

    // Sideways: right of a switch is another device, and left of that one is not the same device.
    const swCore = node(T.swCore);
    swCore.focus();
    fireEvent.keyDown(swCore, { key: "ArrowRight" });
    const right = document.activeElement as HTMLElement;
    expect(right.dataset.id).not.toBe(T.swCore);
    expect(tabStops()).toEqual([right]);
    fireEvent.keyDown(right, { key: "ArrowLeft" });
    const left = document.activeElement as HTMLElement;
    expect(left.dataset.id).not.toBe(right.dataset.id);
    expect(tabStops()).toEqual([left]);
  });

  it("does not select on an arrow key and selects on Space", async () => {
    const view = await openMap();
    const gateway = node(T.gateway);
    gateway.focus();
    fireEvent.keyDown(gateway, { key: "ArrowDown" });
    expect(view.location()).toBe("/topology");
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: " " });
    await waitFor(() => expect(view.location()).toBe(`/topology/${T.swCore}`));
  });

  it("zooms with + and -, fits with 0, and with the buttons", async () => {
    await openMap();
    const fitted = transform();
    const scale = scaleOf();
    expect(scale).toBeGreaterThan(0);
    const gateway = node(T.gateway);
    gateway.focus();

    fireEvent.keyDown(gateway, { key: "+" });
    expect(scaleOf()).toBeGreaterThan(scale);
    fireEvent.keyDown(gateway, { key: "=" });
    const zoomedIn = scaleOf();
    expect(zoomedIn).toBeGreaterThan(scale * 1.5);
    fireEvent.keyDown(gateway, { key: "-" });
    expect(scaleOf()).toBeLessThan(zoomedIn);
    fireEvent.keyDown(gateway, { key: "0" });
    expect(transform()).toBe(fitted);

    fireEvent.click(screen.getByTestId("topology-zoom-in"));
    expect(scaleOf()).toBeGreaterThan(scale);
    fireEvent.click(screen.getByTestId("topology-zoom-out"));
    fireEvent.click(screen.getByTestId("topology-zoom-out"));
    expect(scaleOf()).toBeLessThan(scale);
    fireEvent.click(screen.getByTestId("topology-fit"));
    expect(transform()).toBe(fitted);
    for (const id of ["topology-zoom-in", "topology-zoom-out", "topology-fit"]) {
      expect(screen.getByTestId(id).getAttribute("aria-label")).toBeTruthy();
    }
  });

  it("zooms at the pointer with the wheel and pans by dragging the background", async () => {
    await openMap();
    const svg = screen.getByTestId("topology-map");
    const scale = scaleOf();
    fireEvent.wheel(svg, { deltaY: -200, clientX: 300, clientY: 200 });
    expect(scaleOf()).toBeGreaterThan(scale);
    fireEvent.wheel(svg, { deltaY: 400, clientX: 300, clientY: 200 });
    expect(scaleOf()).toBeLessThan(scale * 1.01);

    const [tx, ty] = translateOf();
    const mouse = (type: string, x: number, y: number) =>
      svg.dispatchEvent(new MouseEvent(type, { bubbles: true, clientX: x, clientY: y, button: 0 }));
    mouse("pointerdown", 100, 100);
    mouse("pointermove", 160, 130);
    const [px, py] = translateOf();
    expect(px - tx).toBeCloseTo(60, 0);
    expect(py - ty).toBeCloseTo(30, 0);
    mouse("pointerup", 160, 130);
    // The pointer is up: moving does not pan any more.
    mouse("pointermove", 400, 400);
    expect(translateOf()).toEqual([px, py]);
    // A drag that starts on a device does not pan.
    node(T.nas).dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, clientX: 5, clientY: 5, button: 0 }));
    mouse("pointermove", 50, 50);
    expect(translateOf()).toEqual([px, py]);
  });
});

describe("live updates", () => {
  it("reads the graph again when intent or observations change, and keeps the focus on its device", async () => {
    stopBridge = bridgeMockEvents();
    await openMap();
    const target = node(T.printer);
    target.focus();
    const requests: string[] = [];
    server.events.on("request:start", ({ request }) => {
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/topology") requests.push(url.search);
    });
    await api.post("/api/v1/sites", { body: { name: "annex" } });
    await waitFor(() => expect(requests.length).toBeGreaterThan(0));
    server.events.removeAllListeners();
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    // The devices stay the same elements, so the focus stays where it was.
    expect(node(T.printer)).toBe(target);
    expect(document.activeElement).toBe(target);
  });
});

describe("states", () => {
  it("says what the map is built from when nothing is known", async () => {
    await answer((graph) => {
      graph.nodes = [];
      graph.edges = [];
      graph.summary = { ...graph.summary, nodes: 0, edges: 0, total_nodes: 0, total_edges: 0, by_kind: {}, by_edge_kind: {}, vlans: [], controllers: [] };
    });
    renderMap();
    const empty = await screen.findByTestId("topology-empty");
    expect(empty.textContent).toContain("Nothing to draw yet");
    expect(empty.textContent).toContain("network controller connector");
    expect(empty.textContent).toContain("SNMP probe");
    expect(empty.textContent).toContain("inventory connectors");
    expect(within(empty).getByRole("link", { name: "Open the connectors" }).getAttribute("href")).toBe("/connectors");
    expect(screen.queryByTestId("topology-map")).toBeNull();
    expect(screen.queryByTestId("topology-controller")).toBeNull();
    expect(screen.getByTestId("topology-summary").textContent).toBe("Showing 0 of 0 devices and 0 of 0 links");
  });

  it("says that nothing matches when a filter leaves no device", async () => {
    renderMap("/topology?q=no-such-device");
    const empty = await screen.findByTestId("topology-empty");
    expect(empty.textContent).toContain("No device matches the filter");
    expect(empty.textContent).not.toContain("Nothing to draw yet");
    expect(screen.getByTestId("topology-summary").textContent).toContain(`Showing 0 of ${TOPOLOGY_COUNTS.nodes} devices`);
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("no-such-device");
  });

  it("shows the loading state first", async () => {
    renderMap();
    expect(screen.getByTestId("topology-loading").textContent).toContain("Loading the map");
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(screen.queryByTestId("topology-loading")).toBeNull();
  });

  it("shows the error of the server in words and tries again", async () => {
    server.use(
      http.get(
        "/api/v1/topology",
        () => HttpResponse.json({ code: "ipam.topology.unavailable", status: 503, title: "Unavailable", detail: "off", params: {} }, { status: 503, headers: PROBLEM }),
        { once: true },
      ),
    );
    renderMap();
    const error = await screen.findByTestId("topology-error");
    expect(error.textContent).toContain("The topology is not available on this server.");
    expect(screen.queryByTestId("topology-map")).toBeNull();
    fireEvent.click(screen.getByTestId("topology-retry"));
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(screen.queryByTestId("topology-error")).toBeNull();
  });

  it("shows a controller that could not be read, with the text of its error", async () => {
    await answer((graph) => {
      graph.summary.controllers = [
        { connector: "7f1d0000-0000-4000-8000-000000000001", name: "unifi.example.test", devices: 0, error: { code: "connect.timeout", status: 504, title: "Timeout", detail: "slow", params: {} } },
        { connector: "7f1d0000-0000-4000-8000-000000000002", name: "other.example.test", devices: 0, error: { code: "no.such.code", status: 500, title: "Odd", detail: "odd", params: {} } },
        { connector: "7f1d0000-0000-4000-8000-000000000003", name: "good.example.test", devices: 3, observed_at: new Date().toISOString() },
      ];
    });
    await openMap();
    const lines = screen.getAllByTestId("topology-controller");
    expect(lines.map((l) => l.dataset.state)).toEqual(["error", "error", "ok"]);
    expect(lines[0]?.textContent).toContain("unifi.example.test");
    expect(lines[0]?.textContent).toContain("The plugin did not answer in time.");
    // An error the UI has no words for still says that the read failed, with the code.
    expect(lines[1]?.textContent).toContain("The last read failed (no.such.code)");
    expect(lines[2]?.textContent).toContain("3 devices read");
  });

  it("says that the answer was cut at the limit", async () => {
    await answer((graph) => {
      graph.summary.truncated = true;
    });
    await openMap();
    expect(screen.getByTestId("topology-truncated").textContent).toContain("The answer was cut at the limit");
  });
});

describe("the drawing", () => {
  it("draws a link that is not part of the spanning tree as a gentle curve", async () => {
    // A second path between the access points closes a loop; one of its links is not a tree link.
    topologyState().edges.push({
      id: "e-0000000000ff",
      kind: "lldp",
      a: T.apGarage,
      a_port: "9",
      b: T.apHall,
      b_port: "9",
      sources: ["probe:1:snmp"],
    });
    await openMap();
    const curves = edges().filter((e) => e.tagName.toLowerCase() === "path");
    expect(curves).toHaveLength(1);
    // Which link of the loop closes it depends on the search order; it is one of the loop.
    const kind = curves[0]?.dataset.kind as string;
    expect(["lldp", "uplink"]).toContain(kind);
    expect(curves[0]?.getAttribute("d")).toMatch(/^M[-\d. ]+Q[-\d. ]+$/);
    expect(edges().filter((e) => e.tagName.toLowerCase() === "line")).toHaveLength(TOPOLOGY_COUNTS.edges);
    expect(curves[0]?.classList.contains(`edge-${kind}`)).toBe(true);
  });

  it("brings a focused device back to the middle when it would leave the screen", async () => {
    await openMap();
    const gateway = node(T.gateway);
    gateway.focus();
    // Zoom in as far as the map goes: the next device is far off the screen.
    for (let i = 0; i < 14; i += 1) fireEvent.keyDown(gateway, { key: "+" });
    expect(scaleOf()).toBe(4);
    const before = transform();

    fireEvent.keyDown(gateway, { key: "ArrowDown" });
    const next = document.activeElement as HTMLElement;
    expect(next.dataset.id).toBe(T.swCore);
    expect(transform()).not.toBe(before);
    const at = /translate\(([-\d.]+) ([-\d.]+)\)/.exec(next.getAttribute("transform") ?? "");
    const [tx, ty] = translateOf();
    const x = Number(at?.[1]) * scaleOf() + tx;
    const y = Number(at?.[2]) * scaleOf() + ty;
    // The map is fitted to 1000 x 640 when the browser gives no size; the device is in the middle.
    expect(x).toBeCloseTo(500, 0);
    expect(y).toBeCloseTo(320, 0);

    // A device that is on the screen does not move the view.
    const stay = transform();
    fireEvent.keyDown(next, { key: "ArrowUp" });
    expect((document.activeElement as HTMLElement).dataset.id).toBe(T.gateway);
    expect(transform()).not.toBe(stay);
  });

  it("keeps the text that is being typed when another filter is chosen", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const view = await openMap();
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "thermo" } });
    fireEvent.click(screen.getByTestId("filter-kind-host"));
    await waitFor(() => expect(view.location()).toBe("/topology?kind=host"));
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("thermo");
    // The pause ends: both filters are in the URL.
    vi.advanceTimersByTime(300);
    await waitFor(() => expect(view.location()).toBe("/topology?kind=host&q=thermo"));
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("thermo");
  });

  it("follows the size of the canvas while the view is the fitted one, and stops once it was zoomed", async () => {
    let notify: (() => void) | undefined;
    vi.stubGlobal(
      "ResizeObserver",
      class {
        constructor(callback: () => void) {
          notify = callback;
        }
        observe() {}
        disconnect() {}
      },
    );
    await openMap();
    const svg = screen.getByTestId("topology-map");
    const box = { width: 1000, height: 640 };
    svg.getBoundingClientRect = () => ({ ...box, x: 0, y: 0, top: 0, left: 0, right: box.width, bottom: box.height, toJSON: () => ({}) });
    const fitted = transform();

    // The panel docks: the canvas gets narrower and the fitted map follows.
    box.width = 400;
    notify?.();
    const narrow = transform();
    expect(narrow).not.toBe(fitted);
    expect(scaleOf()).toBeLessThan(Number(/scale\(([-\d.]+)\)/.exec(fitted)?.[1]));
    box.width = 1000;
    notify?.();
    expect(transform()).toBe(fitted);

    // Once the person zoomed, a change of size leaves the view alone.
    fireEvent.click(screen.getByTestId("topology-zoom-in"));
    const zoomed = transform();
    box.width = 400;
    notify?.();
    expect(transform()).toBe(zoomed);
    // Fit takes the map back to the canvas and makes it follow again.
    fireEvent.click(screen.getByTestId("topology-fit"));
    expect(transform()).toBe(narrow);
    box.width = 1000;
    notify?.();
    expect(transform()).toBe(fitted);
  });

  it("reads the summary as a status", async () => {
    await openMap();
    expect(screen.getByTestId("topology-summary").getAttribute("role")).toBe("status");
  });
});

/** The translation of a drawn device, `translate(x y)`. */
function positionOf(id: string): [number, number] {
  const m = /translate\(([-\d.]+) ([-\d.]+)\)/.exec(node(id).getAttribute("transform") ?? "");
  return [Number(m?.[1]), Number(m?.[2])];
}

/** The first address of a device of the mock lab. */
function addressOf(id: string): string {
  const ip = topologyState().nodes.find((n) => n.id === id)?.ips?.[0];
  if (ip === undefined) throw new Error(`the device ${id} has no address`);
  return ip;
}

/** A device of the mock lab that no source links to anything. */
function addIsolated(id: string, label: string, extra: Partial<components["schemas"]["TopologyNode"]> = {}): string {
  const mac = `00:00:5e:00:${id.slice(-4, -2)}:${id.slice(-2)}`;
  topologyState().nodes.push({ id, kind: "host", label, macs: [mac], subject: mac, sources: ["network_controller:test"], ...extra });
  return id;
}

/** Adds `count` wired clients on one port of a switch; returns their ids. */
function addOnPort(parent: string, port: string, count: number): string[] {
  const ids: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const n = String(i).padStart(2, "0");
    const id = `m-00005e00fe${n}`;
    const mac = `00:00:5e:00:fe:${n}`;
    topologyState().nodes.push({ id, kind: "host", label: `shared-${n}`, macs: [mac], subject: mac, vlans: [10], sources: ["network_controller:test"] });
    topologyState().edges.push({ id: `e-0000000fe0${n}`, kind: "wired", a: parent, a_port: port, b: id, vlan: 10, sources: ["network_controller:test"] });
    ids.push(id);
  }
  return ids;
}

describe("endpoints", () => {
  // The default of the browser: infrastructure first, the switch of the map is off.
  beforeEach(() => {
    localStorage.removeItem(ENDPOINTS_KEY);
  });

  const groupIds = (): string[] => groups().map((g) => g.dataset.id as string).sort();
  // Three devices on iot.example.test under ap-hall, two under ap-garage, and the three guests
  // of pve1, which have no port or SSID, are hidden: eight devices in three groups.
  const COLLAPSED = TOPOLOGY_COUNTS.nodes - 8;
  const HALL = `group:${T.apHall}#${SSID.iot}`;
  const GARAGE = `group:${T.apGarage}#${SSID.iot}`;

  it("collapses the endpoints of one SSID into a group that names the SSID", async () => {
    await openMap("/topology", COLLAPSED);
    expect(groupIds()).toEqual([GARAGE, HALL, `group:${T.pve1}`].sort());
    const hall = groups().find((g) => g.dataset.id === HALL) as HTMLElement;
    expect(hall.dataset.bucket).toBe(SSID.iot);
    expect(hall.dataset.count).toBe("3");
    expect(hall.textContent).toBe("iot.example.test · 3 devices");
    expect(hall.getAttribute("aria-label")).toBe("3 devices on iot.example.test, open the group");
    const garage = groups().find((g) => g.dataset.id === GARAGE) as HTMLElement;
    expect(garage.dataset.count).toBe("2");
    // The virtual machines of a hypervisor have no port or SSID: a group of the whole parent, with no bucket.
    const guests = groups().find((g) => g.dataset.id === `group:${T.pve1}`) as HTMLElement;
    expect(guests.dataset.bucket).toBeUndefined();
    expect(guests.dataset.count).toBe("3");
    expect(guests.textContent).toBe("3 devices");
    // The IoT devices and the guests are not drawn; the one device on its own SSID and the infrastructure are.
    for (const id of [T.plug, T.camera, T.speaker, T.thermostat, T.sensor, T.mediaPc, T.buildVm, T.dnsCt]) expect(nodeIds()).not.toContain(id);
    expect(nodeIds()).toContain(T.tv);
    expect(nodeIds()).toContain(T.guestClient);
    expect(nodes().filter((n) => n.dataset.kind !== "host")).toHaveLength(7);
    // Eight links to the devices become one link per group.
    expect(edges()).toHaveLength(TOPOLOGY_COUNTS.edges - 8 + 3);
    expect(screen.getByTestId("filter-endpoints").getAttribute("aria-pressed")).toBe("false");
  });

  it("collapses the endpoints of one port into a group that names the port", async () => {
    const ids = addOnPort(T.swDesk, "9", 3);
    await openMap("/topology", COLLAPSED + ids.length - 3);
    const group = groups().find((g) => g.dataset.id === `group:${T.swDesk}#9`) as HTMLElement;
    expect(group.dataset.bucket).toBe("9");
    expect(group.dataset.count).toBe("3");
    expect(group.textContent).toBe("9 · 3 devices");
    expect(group.getAttribute("aria-label")).toBe("3 devices on 9, open the group");
    // A device alone on its port stays a device.
    expect(nodeIds()).toContain(T.tenko1);
    expect(nodeIds()).not.toContain(ids[0]);
  });

  it("opens a group on click and shows its members, and only those", async () => {
    await openMap("/topology", COLLAPSED);
    expect(screen.queryByTestId("topology-groups-close")).toBeNull();
    fireEvent.click(groups().find((g) => g.dataset.id === HALL) as HTMLElement);
    await waitFor(() => expect(groups()).toHaveLength(2));
    expect(groupIds()).toEqual([GARAGE, `group:${T.pve1}`].sort());
    expect(nodes()).toHaveLength(COLLAPSED + 3);
    for (const id of [T.plug, T.camera, T.speaker]) expect(nodeIds()).toContain(id);
    for (const id of [T.thermostat, T.sensor, T.mediaPc]) expect(nodeIds()).not.toContain(id);
    expect(edges()).toHaveLength(TOPOLOGY_COUNTS.edges - 5 + 2);

    fireEvent.click(screen.getByTestId("topology-groups-close"));
    await waitFor(() => expect(groups()).toHaveLength(3));
  });

  it("shows every endpoint with the Endpoints chip and remembers the choice in the browser", async () => {
    await openMap("/topology", COLLAPSED);
    const chip = screen.getByTestId("filter-endpoints");
    expect(chip.textContent).toBe("Endpoints");
    expect(chip.getAttribute("aria-pressed")).toBe("false");
    expect(localStorage.getItem(ENDPOINTS_KEY)).toBeNull();

    fireEvent.click(chip);
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
    expect(groups()).toHaveLength(0);
    expect(edges()).toHaveLength(TOPOLOGY_COUNTS.edges);
    expect(screen.getByTestId("filter-endpoints").getAttribute("aria-pressed")).toBe("true");
    expect(localStorage.getItem(ENDPOINTS_KEY)).toBe("all");

    // A new page load starts the way the person left it.
    cleanup();
    await openMap();
    expect(groups()).toHaveLength(0);
    expect(screen.getByTestId("filter-endpoints").getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(screen.getByTestId("filter-endpoints"));
    await waitFor(() => expect(groups()).toHaveLength(3));
    expect(localStorage.getItem(ENDPOINTS_KEY)).toBeNull();
    expect(screen.getByTestId("filter-endpoints").getAttribute("aria-pressed")).toBe("false");
  });

  it("keeps working for the page when the browser refuses storage", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    try {
      await openMap("/topology", COLLAPSED);
      fireEvent.click(screen.getByTestId("filter-endpoints"));
      await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
      expect(screen.getByTestId("filter-endpoints").getAttribute("aria-pressed")).toBe("true");
    } finally {
      vi.restoreAllMocks();
    }
  });
});

describe("inferred links", () => {
  it("draws a link only a MAC table names dashed with a question mark and lists it in the legend", async () => {
    await openMap();
    const graph = await graphOf();
    const inferred = graph.edges.filter((e) => e.inferred === true);
    expect(inferred).toHaveLength(1);
    expect(inferred[0]?.b).toBe(T.printer);

    const drawn = edges().filter((e) => e.dataset.inferred === "true");
    expect(drawn.map((e) => e.dataset.id)).toEqual([inferred[0]?.id]);
    expect(drawn[0]?.dataset.kind).toBe("wired");
    expect(drawn[0]?.classList.contains("edge-inferred")).toBe(true);
    // The links that a controller reports are not marked.
    expect(edges().filter((e) => e.dataset.inferred !== undefined)).toHaveLength(1);
    expect(edges().filter((e) => e.classList.contains("edge-inferred"))).toHaveLength(1);

    const marks = screen.getAllByTestId("topology-edge-inferred");
    expect(marks).toHaveLength(1);
    expect(marks[0]?.textContent).toContain("?");
    expect(marks[0]?.querySelector("title")?.textContent).toBe("inferred from the MAC table");

    const entry = within(screen.getByTestId("topology-legend"))
      .getAllByTestId("legend-edge")
      .find((li) => li.dataset.kind === "inferred") as HTMLElement;
    expect(entry.textContent).toBe("Inferred from the MAC table (?)");
    expect(entry.querySelector("line")?.classList.contains("edge-inferred")).toBe(true);
  });

  it("has neither mark nor legend entry when no drawn link is inferred", async () => {
    await openMap("/topology?kind=router,switch,access_point", 6);
    expect(edges().filter((e) => e.dataset.inferred !== undefined)).toHaveLength(0);
    expect(screen.queryAllByTestId("topology-edge-inferred")).toHaveLength(0);
    expect(within(screen.getByTestId("topology-legend")).getAllByTestId("legend-edge").map((li) => li.dataset.kind)).not.toContain("inferred");
  });
});

describe("devices with a hashed name", () => {
  it("shows the vendor and the address as a second line", async () => {
    const id = "m-00005e00ff01";
    const label = "host-00005e00ff01";
    topologyState().nodes.push({
      id,
      kind: "host",
      label,
      macs: ["00:00:5e:00:ff:01"],
      subject: "00:00:5e:00:ff:01",
      vendor: "Acme",
      ips: ["192.0.2.77"],
      vlans: [10],
      sources: ["network_controller:test"],
    });
    topologyState().edges.push({ id: "e-0000000000a1", kind: "wired", a: T.swDesk, a_port: "9", b: id, vlan: 10, sources: ["network_controller:test"] });
    await openMap("/topology", TOPOLOGY_COUNTS.nodes + 1);
    const second = within(node(id)).getByTestId("topology-node-second");
    expect(second.textContent).toBe("Acme · 192.0.2.77");
    expect(node(id).querySelector("text.label")?.textContent).toBe(label);
    expect(node(id).getAttribute("aria-label")).toBe(`${label}, Host`);
    // A device with a name that says something has no second line, and neither has a made-up vendor label.
    expect(screen.getAllByTestId("topology-node-second")).toHaveLength(1);
    expect(within(node(T.unknown)).queryByTestId("topology-node-second")).toBeNull();
    expect(within(node(T.gateway)).queryByTestId("topology-node-second")).toBeNull();
  });

  it("leaves the second line out when the device has neither vendor nor address", async () => {
    const id = "m-00005e00ff03";
    topologyState().nodes.push({ id, kind: "host", label: "host-00005e00ff03", macs: ["00:00:5e:00:ff:03"], subject: "00:00:5e:00:ff:03", sources: ["network_controller:test"] });
    topologyState().edges.push({ id: "e-0000000000a3", kind: "wired", a: T.swDesk, a_port: "9", b: id, sources: ["network_controller:test"] });
    await openMap("/topology", TOPOLOGY_COUNTS.nodes + 1);
    expect(within(node(id)).queryByTestId("topology-node-second")).toBeNull();
  });
});

describe("not placed", () => {
  it("lists a device no source links to and does not draw it", async () => {
    const id = addIsolated("m-00005e00ff02", "lonely-host");
    await openMap();
    expect(nodeIds()).not.toContain(id);
    const section = screen.getByTestId("topology-unplaced");
    expect(section.querySelector("h2")?.textContent).toBe("Not placed · 1");
    const items = within(section).getAllByTestId("topology-unplaced-device");
    expect(items.map((li) => li.dataset.id)).toEqual([id]);
    expect(items[0]?.textContent).toContain("lonely-host");
    expect(items[0]?.textContent).toContain("Host");
    expect(within(section).queryByTestId("topology-duplicate")).toBeNull();
    expect(section.getAttribute("aria-label")).toBe("Devices not placed on the map");
    // The summary still counts it.
    expect(screen.getByTestId("topology-summary").textContent).toContain(`Showing ${TOPOLOGY_COUNTS.nodes + 1} of ${TOPOLOGY_COUNTS.nodes + 1} devices`);
  });

  it("has no list when every device is placed", async () => {
    await openMap();
    expect(screen.queryByTestId("topology-unplaced")).toBeNull();
  });

  it("opens the panel of an unplaced device from the list", async () => {
    const id = addIsolated("m-00005e00ff02", "lonely-host");
    const view = await openMap();
    fireEvent.click(within(screen.getByTestId("topology-unplaced-device")).getByRole("button", { name: "lonely-host" }));
    await waitFor(() => expect(view.location()).toBe(`/topology/${id}`));
    expect((await screen.findByTestId("node-panel")).dataset.id).toBe(id);
    expect(screen.getByTestId("topology-unplaced-device").querySelector("button")?.getAttribute("aria-current")).toBe("true");
    expect(nodeIds()).not.toContain(id);
  });

  it("marks an unplaced device with the label of another device as a duplicate", async () => {
    addIsolated("m-00005e00ff02", "NAS");
    await openMap();
    const mark = screen.getByTestId("topology-duplicate");
    expect(mark.textContent).toBe("Duplicate");
    expect(mark.getAttribute("title")).toBe("nas");
  });

  it("marks an unplaced device with the address of another device as a duplicate", async () => {
    addIsolated("m-00005e00ff02", "old-tenko", { ips: [addressOf(T.tenko1)] });
    await openMap();
    const mark = screen.getByTestId("topology-duplicate");
    expect(mark.textContent).toBe("Duplicate");
    expect(mark.getAttribute("title")).toBe("tenko1");
  });

  it("counts the duplicates when several devices share a label or an address", async () => {
    addIsolated("m-00005e00ff02", "nas", { ips: [addressOf(T.tenko1)] });
    await openMap();
    const mark = screen.getByTestId("topology-duplicate");
    expect(mark.textContent).toBe("2 duplicates");
    expect((mark.getAttribute("title") ?? "").split(", ").sort()).toEqual(["nas", "tenko1"]);
  });

  it("gathers nothing while a kind filter is on, because the filter drops the links", async () => {
    const id = addIsolated("m-00005e00ff02", "lonely-host");
    await openMap("/topology?kind=host", 16);
    expect(nodeIds()).toContain(id);
    expect(screen.queryByTestId("topology-unplaced")).toBeNull();
  });

  it("speaks Swedish", async () => {
    addIsolated("m-00005e00ff02", "lonely-host");
    const { setLocale } = await import("../i18n");
    await setLocale("sv");
    try {
      await openMap();
      expect(screen.getByTestId("topology-unplaced").querySelector("h2")?.textContent).toBe("Inte placerade · 1");
    } finally {
      await setLocale("en");
    }
  });
});

describe("the root of the map", () => {
  /** The default route points at sw-desk while the controller names the gateway. */
  function disagree(): string {
    const ip = addressOf(T.swDesk);
    topologyState().nextHops = [ip];
    return ip;
  }

  it("draws the map from the root the summary names", async () => {
    await openMap();
    expect((await graphOf()).summary.root).toEqual({ source: "controller", chosen: false, node: T.gateway });
    const [, top] = positionOf(T.gateway);
    for (const n of nodes()) expect(positionOf(n.dataset.id as string)[1]).toBeGreaterThanOrEqual(top);
    // The root is the first tree and the one the keyboard starts at.
    expect(positionOf(T.swDesk)[1]).toBeGreaterThan(top);
  });

  it("lists two candidates when the sources disagree and draws from the first until the person chooses", async () => {
    disagree();
    await openMap();
    const notice = await screen.findByTestId("topology-root-notice");
    expect(within(notice).getAllByTestId("topology-root-candidate").map((c) => c.dataset.source)).toEqual(["controller", "default_route"]);
    expect(notice.textContent).toContain("gw (controller)");
    expect(notice.textContent).toContain("sw-desk (default route)");
    expect(within(notice).getAllByTestId("topology-root-use")).toHaveLength(2);
    expect(positionOf(T.gateway)[1]).toBeLessThan(positionOf(T.swDesk)[1]);
  });

  it("stores \"Use this\", redraws the map from the chosen root and does not ask again", async () => {
    disagree();
    await openMap();
    const notice = await screen.findByTestId("topology-root-notice");
    const route = within(notice).getAllByTestId("topology-root-candidate").find((c) => c.dataset.source === "default_route") as HTMLElement;
    fireEvent.click(within(route).getByTestId("topology-root-use"));
    await waitFor(() => expect(screen.queryByTestId("topology-root-notice")).toBeNull());
    expect((await graphOf()).summary.root).toEqual({ source: "default_route", chosen: true, node: T.swDesk });
    // sw-desk is the root now: nothing is drawn above it, and the gateway moved down.
    await waitFor(() => expect(positionOf(T.swDesk)[1]).toBeLessThan(positionOf(T.gateway)[1]));
    for (const n of nodes()) expect(positionOf(n.dataset.id as string)[1]).toBeGreaterThanOrEqual(positionOf(T.swDesk)[1]);

    // A new page does not bring the note back.
    cleanup();
    let answered = 0;
    server.events.on("response:mocked", ({ request }) => {
      if (new URL(request.url).pathname === "/api/v1/topology/root") answered += 1;
    });
    await openMap();
    await waitFor(() => expect(answered).toBeGreaterThan(0));
    await new Promise((resolve) => setTimeout(resolve, 30));
    server.events.removeAllListeners();
    expect(screen.queryByTestId("topology-root-notice")).toBeNull();
    expect(positionOf(T.swDesk)[1]).toBeLessThan(positionOf(T.gateway)[1]);
  });
});

describe("the view switch", () => {
  const tabs = () => [screen.getByTestId("topology-view-map"), screen.getByTestId("topology-view-ssids")];

  it("starts on the map, with the map tab selected and the only one in the tab order", async () => {
    await openMap();
    expect(screen.getByTestId("topology-view-switch").getAttribute("role")).toBe("tablist");
    expect(screen.getByTestId("topology-view-switch").getAttribute("aria-label")).toBe("Topology views");
    expect(tabs().map((tab) => tab.getAttribute("aria-selected"))).toEqual(["true", "false"]);
    expect(tabs().map((tab) => tab.getAttribute("tabindex"))).toEqual(["0", "-1"]);
    expect(tabs().map((tab) => tab.textContent)).toEqual(["Map", "SSIDs"]);
    expect(screen.queryByTestId("ssid-view")).toBeNull();
  });

  it("shows the SSID view with view=ssids in the URL and returns to the map", async () => {
    const view = await openMap();
    fireEvent.click(screen.getByTestId("topology-view-ssids"));
    await waitFor(() => expect(view.location()).toBe("/topology?view=ssids"));
    expect(screen.getByTestId("ssid-view")).toBeTruthy();
    await waitFor(() => expect(screen.getAllByTestId("ssid-row")).toHaveLength(3));
    expect(screen.queryByTestId("topology-map")).toBeNull();
    expect(screen.queryByTestId("filterbar")).toBeNull();
    expect(tabs().map((tab) => tab.getAttribute("aria-selected"))).toEqual(["false", "true"]);
    expect(tabs().map((tab) => tab.getAttribute("tabindex"))).toEqual(["-1", "0"]);

    fireEvent.click(screen.getByTestId("topology-view-map"));
    await waitFor(() => expect(view.location()).toBe("/topology"));
    expect(screen.queryByTestId("ssid-view")).toBeNull();
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));
  });

  it("opens on the SSID view when the URL says so", async () => {
    renderMap("/topology?view=ssids");
    await waitFor(() => expect(screen.getAllByTestId("ssid-row")).toHaveLength(3));
    expect(screen.queryByTestId("topology-map")).toBeNull();
    expect(screen.getByTestId("topology-view-ssids").getAttribute("aria-selected")).toBe("true");
  });

  it("keeps the filters of the map in the URL while the other view is open", async () => {
    const view = await openMap("/topology?vlan=30", (await graphOf({ vlan: "30" })).nodes.length);
    fireEvent.click(screen.getByTestId("topology-view-ssids"));
    await waitFor(() => expect(view.location()).toBe("/topology?vlan=30&view=ssids"));
    fireEvent.click(screen.getByTestId("topology-view-map"));
    await waitFor(() => expect(view.location()).toBe("/topology?vlan=30"));
  });

  it("moves between the two tabs with the arrow keys and focuses the one it moved to", async () => {
    const view = await openMap();
    const [map, ssids] = tabs() as [HTMLElement, HTMLElement];
    map.focus();
    fireEvent.keyDown(map, { key: "ArrowRight" });
    await waitFor(() => expect(view.location()).toBe("/topology?view=ssids"));
    expect(document.activeElement).toBe(ssids);
    expect(screen.getByTestId("ssid-view")).toBeTruthy();

    fireEvent.keyDown(ssids, { key: "ArrowLeft" });
    await waitFor(() => expect(view.location()).toBe("/topology"));
    expect(document.activeElement).toBe(map);
    await waitFor(() => expect(nodes()).toHaveLength(TOPOLOGY_COUNTS.nodes));

    // With two tabs the other direction also reaches the other tab.
    fireEvent.keyDown(map, { key: "ArrowLeft" });
    await waitFor(() => expect(view.location()).toBe("/topology?view=ssids"));
    expect(document.activeElement).toBe(ssids);
    fireEvent.keyDown(ssids, { key: "ArrowRight" });
    await waitFor(() => expect(view.location()).toBe("/topology"));
    expect(document.activeElement).toBe(map);
    // Other keys do nothing.
    fireEvent.keyDown(map, { key: "ArrowDown" });
    expect(view.location()).toBe("/topology");
  });
});

describe("Hardened, read-only", () => {
  async function signInHardened(writes: boolean): Promise<void> {
    await signInAlex({
      prepare: () => {
        db.settings.profile = "hardened";
      },
    });
    mockVlanController.writes_enabled = writes;
  }

  /** The default route points at sw-desk, so the root note is open. */
  function disagree(): void {
    topologyState().nextHops = [addressOf(T.swDesk)];
  }

  const waitForSsids = () => waitFor(() => expect(screen.getAllByTestId("ssid-row")).toHaveLength(3));

  it("says the map is read-only and offers no choice of the root when no controller allows writes", async () => {
    await signInHardened(false);
    disagree();
    await openMap();
    expect(screen.getByTestId("topology-read-only").textContent).toContain("Read-only");
    const notice = await screen.findByTestId("topology-root-notice");
    expect(within(notice).getAllByTestId("topology-root-candidate")).toHaveLength(2);
    expect(screen.queryAllByTestId("topology-root-use")).toHaveLength(0);
  });

  it("offers no write action in the SSID view either", async () => {
    await signInHardened(false);
    renderMap("/topology?view=ssids");
    await waitForSsids();
    await waitFor(() => expect(screen.getByTestId("ssid-read-only")).toBeTruthy());
    expect(screen.queryAllByTestId("ssid-client-keep")).toHaveLength(0);
    expect(screen.queryAllByTestId("ssid-client-move")).toHaveLength(0);
    for (const chip of screen.getAllByTestId("ssid-policy")) expect(chip.tagName).toBe("SPAN");
  });

  it("offers the choice of the root and the SSID actions when a controller allows writes", async () => {
    await signInHardened(true);
    disagree();
    await openMap();
    await screen.findByTestId("topology-root-notice");
    expect(screen.queryByTestId("topology-read-only")).toBeNull();
    expect(screen.getAllByTestId("topology-root-use")).toHaveLength(2);

    fireEvent.click(screen.getByTestId("topology-view-ssids"));
    await waitForSsids();
    await waitFor(() => expect(screen.getAllByTestId("ssid-client-keep")).toHaveLength(1));
    expect(screen.queryByTestId("ssid-read-only")).toBeNull();
    expect(screen.getAllByTestId("ssid-client-move")).toHaveLength(1);
    for (const chip of screen.getAllByTestId("ssid-policy")) expect(chip.tagName).toBe("BUTTON");
  });

  it("is not read-only under the Standard profile, whatever the controller allows", async () => {
    mockVlanController.writes_enabled = false;
    disagree();
    await openMap();
    await screen.findByTestId("topology-root-notice");
    expect(screen.queryByTestId("topology-read-only")).toBeNull();
    expect(screen.getAllByTestId("topology-root-use")).toHaveLength(2);
  });
});

describe("accessibility", () => {
  it("has no axe violations without the panel", async () => {
    await openMap();
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });

  it("has no axe violations with the panel and an opened port", async () => {
    await openMap(`/topology/${T.swCore}`);
    await screen.findByTestId("node-label");
    const open = within(await screen.findByTestId("node-ports")).getAllByTestId("node-port-open")[2] as HTMLElement;
    fireEvent.click(open);
    await screen.findByTestId("port-neighbours");
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });

  it("has no axe violations in the empty state", async () => {
    renderMap("/topology?q=no-such-device");
    await screen.findByTestId("topology-empty");
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });

  it("has no axe violations with a group", async () => {
    addClients(T.swDesk, 10);
    await openMap("/topology", TOPOLOGY_COUNTS.nodes + 10 - 15);
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });

  it("has no axe violations with collapsed endpoints, a root note and a device that is not placed", async () => {
    localStorage.removeItem(ENDPOINTS_KEY);
    topologyState().nextHops = [addressOf(T.swDesk)];
    addIsolated("m-00005e00ff02", "NAS");
    await openMap("/topology", TOPOLOGY_COUNTS.nodes - 8);
    await screen.findByTestId("topology-root-notice");
    expect(screen.getByTestId("topology-duplicate")).toBeTruthy();
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });

  it("has no axe violations in the SSID view", async () => {
    renderMap("/topology?view=ssids");
    await waitFor(() => expect(screen.getAllByTestId("ssid-row")).toHaveLength(3));
    expect(await axeViolations(screen.getByTestId("page-topology"))).toEqual([]);
  });
});
