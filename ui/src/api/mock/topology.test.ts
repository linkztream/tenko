// The topology map of the mock API through `fetch` against the msw server: the seeded graph
// and its consistency with the IPAM seed, the filters with the context rule of the server,
// the limit, the view of one node with its ports, neighbours and intent, the root of the map
// (UI-Q10), the SSID view with the two WLAN rules and the decisions stored on them.
import { beforeEach, describe, expect, it } from "vitest";
import { apiOperations } from "../generated/operations";
import type { components } from "../generated/schema";
import { signInWithRoles } from "../../auth/scope-testkit";
import { db, resetMockDb } from "./db";
import { HOST_IDS, IPAM_IDS, applyCommands, ipamState } from "./ipam/api";
import { mockTopologyDecisions } from "./topology-decisions";
import { TOPOLOGY_COUNTS, TOPOLOGY_IDS, TOPOLOGY_SOURCES, TOPOLOGY_SSIDS, mockVlanController, topologyState } from "./topology-store";

type S = components["schemas"];
type Graph = S["TopologyGraph"];
type NodeView = S["TopologyNodeView"];

interface Problem {
  type: string;
  status: number;
  code: string;
  title: string;
  detail: string;
  params: Record<string, string>;
}
interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

async function get<T>(path: string): Promise<Answer<T>> {
  const res = await fetch(path, { headers: { accept: "application/json" } });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

async function send<T>(method: string, path: string, json?: unknown, headers: Record<string, string> = {}): Promise<Answer<T>> {
  const all: Record<string, string> = { accept: "application/json", ...headers };
  if (json !== undefined) all["content-type"] = "application/json";
  const res = await fetch(path, { method, headers: all, body: json === undefined ? null : JSON.stringify(json) });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

function expectProblem(answer: Answer<unknown>, status: number, code: string): Problem {
  expect(answer.status, JSON.stringify(answer.body)).toBe(status);
  expect(answer.res.headers.get("content-type")).toContain("application/problem+json");
  const body = answer.body as Problem;
  expect(body.type).toBe("about:blank");
  expect(body.code).toBe(code);
  expect(body.params).toBeTypeOf("object");
  return body;
}

const V = "/api/v1";
const T = TOPOLOGY_IDS;
const NETWORK_DEVICES = [T.gateway, T.swCore, T.swDesk, T.apHall, T.apGarage, T.apAttic];
const IOT = [T.thermostat, T.plug, T.camera, T.speaker, T.sensor];

const graph = async (query = ""): Promise<Graph> => {
  const answer = await get<Graph>(`${V}/topology${query}`);
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body;
};
const ids = (g: Graph): string[] => g.nodes.map((n) => n.id).sort();
const sorted = (list: readonly string[]): string[] => [...list].sort();

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the topology operations of the document", () => {
  it("are answered, each after the session check", async () => {
    const operations = apiOperations.filter((o) => o.path.startsWith("/api/v1/topology"));
    expect(operations.map((o) => `${o.method} ${o.path}`).sort()).toEqual([
      "delete /api/v1/topology/root",
      "delete /api/v1/topology/ssids/{ssid}/exceptions/{host}",
      "delete /api/v1/topology/ssids/{ssid}/policy",
      "get /api/v1/topology",
      "get /api/v1/topology/nodes/{id}",
      "get /api/v1/topology/root",
      "get /api/v1/topology/ssids",
      "put /api/v1/topology/root",
      "put /api/v1/topology/ssids/{ssid}/exceptions/{host}",
      "put /api/v1/topology/ssids/{ssid}/policy",
    ]);
    for (const operation of operations) {
      const path = operation.path.replace("{id}", T.swCore).replace("{ssid}", "home.example.test").replace("{host}", HOST_IDS.nas as string);
      if (operation.method === "get") {
        resetMockDb("signed-in");
        expect((await get(path)).status, path).toBe(200);
      }
      resetMockDb("signed-out");
      expectProblem(await send(operation.method.toUpperCase(), path, operation.method === "put" ? { source: "controller", policy: "track" } : undefined), 401, "auth.unauthenticated");
    }
  });
});

describe("the seeded graph", () => {
  it("has the nodes, edges and counts of the lab", async () => {
    const g = await graph();
    expect(g.nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
    expect(g.edges).toHaveLength(TOPOLOGY_COUNTS.edges);
    expect(g.revision).toBe(db.revision);
    expect(g.nodes.map((n) => n.id)).toEqual(sorted(g.nodes.map((n) => n.id)));
    expect(g.edges.map((e) => e.id)).toEqual(sorted(g.edges.map((e) => e.id)));
    expect(g.summary).toMatchObject({
      nodes: TOPOLOGY_COUNTS.nodes,
      edges: TOPOLOGY_COUNTS.edges,
      total_nodes: TOPOLOGY_COUNTS.nodes,
      total_edges: TOPOLOGY_COUNTS.edges,
      truncated: false,
      by_kind: { access_point: 3, container: 1, host: 15, hypervisor: 1, router: 1, switch: 2, vm: 2 },
      by_edge_kind: { lldp: 1, uplink: 4, vm_host: 3, wired: 9, wireless: 7 },
    });
    // Every id the tests export is a node, and every edge joins two nodes.
    const known = new Set(g.nodes.map((n) => n.id));
    for (const [name, id] of Object.entries(T)) if (name !== "controller") expect(known.has(id), name).toBe(true);
    for (const edge of g.edges) {
      expect(known.has(edge.a), edge.id).toBe(true);
      expect(known.has(edge.b), edge.id).toBe(true);
      expect(edge.id).toMatch(/^e-[0-9a-f]{12}$/);
    }
    // The map is one tree: connected, no cycle.
    expect(g.edges.length).toBe(g.nodes.length - 1);
  });

  it("follows the identifier rules of the server", async () => {
    const g = await graph();
    for (const node of g.nodes) {
      if (node.host) {
        expect(node.id).toBe(`h-${node.host.replace(/-/g, "")}`);
        expect(node.sources).toContain("intent");
      } else if (node.id.startsWith("c-") || node.id.startsWith("i-")) {
        expect(node.id).toMatch(/^[ci]-[0-9a-f]{12}$/);
        expect(node.sources).not.toContain("intent");
      } else {
        expect(node.id).toBe(`m-${node.macs?.[0]?.replace(/:/g, "")}`);
      }
      expect(node.subject).toBe(node.macs?.[0] ?? node.ips?.[0]);
      expect(node.sources).toEqual(sorted(node.sources));
      expect(Date.parse(node.last_seen ?? "")).toBeLessThanOrEqual(Date.now());
    }
    const byId = new Map(g.nodes.map((n) => [n.id, n] as const));
    expect(byId.get(T.apAttic)?.host).toBeUndefined();
    expect(byId.get(T.mediaPc)?.id.startsWith("i-")).toBe(true);
    expect(byId.get(T.unknown)).toMatchObject({ kind: "host", vendor: "Example Devices", label: "Example Devices 00:53:d2" });
    expect(byId.get(T.unknown)?.host).toBeUndefined();
  });

  it("matches the hosts, addresses, networks, VLANs and sites of the IPAM seed", async () => {
    const g = await graph();
    const data = ipamState().data;
    const byId = new Map(g.nodes.map((n) => [n.id, n] as const));
    for (const node of g.nodes.filter((n) => n.host)) {
      const host = data.host.get(node.host ?? "");
      expect(host?.name, node.id).toBe(node.label);
      const interfaces = [...data.interface.values()].filter((i) => i.host === host?.id);
      expect(node.macs ?? []).toEqual(interfaces.flatMap((i) => (i.mac ? [i.mac] : [])).sort());
      for (const ip of node.ips ?? []) {
        const address = [...data.address.values()].find((a) => a.ip === ip && interfaces.some((i) => i.id === a.interface));
        expect(address, `${node.label} ${ip}`).toBeDefined();
        expect(node.prefixes).toContain(address?.prefix);
      }
    }
    expect(byId.get(T.printer)).toMatchObject({ ips: ["192.0.2.30"], macs: ["00:00:5e:00:53:1e"], prefixes: [IPAM_IDS.prefix.lan] });
    expect(byId.get(T.sensor)).toMatchObject({ ips: ["198.51.100.44"], prefixes: [IPAM_IDS.prefix.iot], vlans: [30] });
    // gw has an IPv6 address on the same interface.
    expect(byId.get(T.gateway)).toMatchObject({
      kind: "router",
      ips: ["192.0.2.1", "2001:db8:0:10::1"],
      prefixes: [IPAM_IDS.prefix.lan, IPAM_IDS.prefix.lanV6],
    });
    // Sites: the host's, else the network's. Only ap-garage is in the Garage.
    expect(byId.get(T.apGarage)?.site).toBe(IPAM_IDS.site.garage);
    for (const node of g.nodes.filter((n) => n.id !== T.apGarage && n.id !== T.unknown && n.id !== T.guestClient)) {
      expect(node.site, node.label).toBe(IPAM_IDS.site.home);
    }
    expect(byId.get(T.unknown)?.site).toBeUndefined();
    expect(byId.get(T.guestClient)?.site).toBeUndefined();
    expect(g.summary.sites).toEqual([IPAM_IDS.site.home, IPAM_IDS.site.garage]);
    expect(HOST_IDS.gw).toBe(byId.get(T.gateway)?.host);
  });

  it("has the network devices, the hypervisor with its guests and the wired and wireless clients", async () => {
    const g = await graph();
    const byId = new Map(g.nodes.map((n) => [n.id, n] as const));
    const kinds: Record<string, string> = {
      [T.gateway]: "router",
      [T.swCore]: "switch",
      [T.swDesk]: "switch",
      [T.apHall]: "access_point",
      [T.apGarage]: "access_point",
      [T.apAttic]: "access_point",
      [T.pve1]: "hypervisor",
      [T.mediaPc]: "vm",
      [T.buildVm]: "vm",
      [T.dnsCt]: "container",
    };
    for (const [id, kind] of Object.entries(kinds)) expect(byId.get(id)?.kind, id).toBe(kind);
    const edge = (kind: string, a: string, b: string) => g.edges.find((e) => e.kind === kind && e.a === a && e.b === b);
    // Virtual machines hang on their hypervisor.
    for (const guest of [T.mediaPc, T.buildVm, T.dnsCt]) {
      expect(edge("vm_host", T.pve1, guest)?.sources).toEqual([TOPOLOGY_SOURCES.inventory]);
    }
    // pve1 is wired to sw-core, the IoT devices are wireless on the access points over iot.example.test.
    expect(edge("wired", T.swCore, T.pve1)).toMatchObject({ a_port: "2", vlan: 10 });
    for (const [ap, client] of [
      [T.apHall, T.plug],
      [T.apHall, T.camera],
      [T.apHall, T.speaker],
      [T.apGarage, T.thermostat],
      [T.apGarage, T.sensor],
    ] as const) {
      expect(edge("wireless", ap, client), `${ap} ${client}`).toMatchObject({ ssid: TOPOLOGY_SSIDS.iot, vlan: 30 });
      expect(byId.get(client)?.ssids).toEqual([TOPOLOGY_SSIDS.iot]);
      expect(byId.get(client)?.vlans).toContain(30);
    }
    expect(edge("wireless", T.apHall, T.tv)).toMatchObject({ ssid: TOPOLOGY_SSIDS.home, vlan: 10 });
    expect(byId.get(T.apHall)?.ssids).toEqual([TOPOLOGY_SSIDS.home, TOPOLOGY_SSIDS.iot]);
    expect(byId.get(T.apGarage)?.ssids).toEqual([TOPOLOGY_SSIDS.iot]);
    // The lab hosts are on VLAN 20, the rest of the wired hosts on VLAN 10.
    for (const lab of [T.tenko1, T.tenko2, T.tenko3]) expect(g.edges.find((e) => e.b === lab)?.vlan).toBe(20);
    for (const wired of [T.nas, T.ha, T.printer, T.laptop, T.unknown]) expect(g.edges.find((e) => e.b === wired)?.vlan).toBe(10);
    // Links between devices have no direction: the smaller identifier comes first.
    const links = g.edges.filter((e) => e.kind === "lldp" || e.kind === "uplink");
    expect(links).toHaveLength(5);
    for (const link of links) expect(link.a < link.b, link.id).toBe(true);
    expect(g.edges.find((e) => e.kind === "lldp")).toMatchObject({ a: T.swCore, a_port: "6", b: T.swDesk, b_port: "1" });
    expect(g.edges.find((e) => e.kind === "lldp")?.sources).toEqual([TOPOLOGY_SOURCES.controller, TOPOLOGY_SOURCES.snmp].sort());
    expect(g.edges.find((e) => e.kind === "uplink" && e.a === T.gateway)).toMatchObject({ a_port: "1", b: T.swCore, b_port: "1" });
    // The access points have uplink edges to the switches.
    for (const [ap, sw] of [
      [T.apHall, T.swCore],
      [T.apGarage, T.swDesk],
      [T.apAttic, T.swDesk],
    ] as const) {
      expect(links.some((l) => [l.a, l.b].includes(ap) && [l.a, l.b].includes(sw)), `${ap} ${sw}`).toBe(true);
    }
  });

  it("summarizes the VLANs with the names of the IPAM mock, the controller and its networks", async () => {
    const g = await graph();
    expect(g.summary.vlans.map((v) => [v.vid, v.name, v.vlan])).toEqual([
      [10, "LAN", IPAM_IDS.vlan.v10],
      [20, "Lab", IPAM_IDS.vlan.v20],
      [30, "IoT", IPAM_IDS.vlan.v30],
      [40, "DMZ", IPAM_IDS.vlan.v40],
    ]);
    for (const entry of g.summary.vlans) expect(entry.nodes).toBe(g.nodes.filter((n) => n.vlans?.includes(entry.vid)).length);
    expect(g.summary.controllers).toEqual([
      { connector: T.controller, name: "unifi.example.test", observed_at: g.summary.computed_at, devices: TOPOLOGY_COUNTS.controllerDevices, writes_enabled: true },
    ]);
    expect(g.summary.networks).toEqual([
      { id: "net-mgmt", name: "Management", vlan: 10, subnet: "192.0.2.0/24", management: true, dhcp: "server", connector: T.controller },
      { id: "net-iot", name: "IoT", vlan: 30, subnet: "198.51.100.0/24", management: false, dhcp: "relay", connector: T.controller },
    ]);
    expect(Date.parse(g.summary.computed_at ?? "")).toBeLessThanOrEqual(Date.now());
    // A VLAN renamed in IPAM is renamed in the legend.
    applyCommands([{ op: "update_vlan", args: { id: IPAM_IDS.vlan.v30, expected: null, patch: { name: "Things" } } }] as never);
    expect((await graph()).summary.vlans.find((v) => v.vid === 30)?.name).toBe("Things");
  });

});

describe("the filters", () => {
  it("keep the nodes of a site, with the network devices as context", async () => {
    // ap-garage is the only node of the Garage; the backbone completes the picture.
    const garage = await graph(`?site=${IPAM_IDS.site.garage}`);
    expect(ids(garage)).toEqual(sorted(NETWORK_DEVICES));
    expect(garage.summary).toMatchObject({ nodes: 6, edges: 5, total_nodes: TOPOLOGY_COUNTS.nodes, total_edges: TOPOLOGY_COUNTS.edges, truncated: false });
    expect(garage.summary.sites).toEqual([IPAM_IDS.site.home, IPAM_IDS.site.garage]);
    // Exactly the hosts of a site, without context: the unknown client has no site.
    const home = await graph(`?site=${IPAM_IDS.site.home}&kind=host`);
    expect(home.nodes).toHaveLength(13);
    expect(home.nodes.every((n) => n.kind === "host" && n.site === IPAM_IDS.site.home)).toBe(true);
    expect(ids(home)).not.toContain(T.unknown);
    expect(home.edges).toEqual([]);
    expect((await graph(`?site=${IPAM_IDS.site.lab}`)).nodes).toEqual([]);
    expect((await graph(`?site=${IPAM_IDS.site.lab}`)).summary).toMatchObject({ nodes: 0, edges: 0, total_nodes: TOPOLOGY_COUNTS.nodes, vlans: [], sites: [] });
    expectProblem(await get(`${V}/topology?site=garage`), 400, "sys.invalid_query");
  });

  it("keep the nodes of a VLAN: a VLAN id or the identifier of a VLAN object", async () => {
    const lab = await graph("?vlan=20");
    expect(ids(lab)).toEqual(sorted([T.tenko1, T.tenko2, T.tenko3, ...NETWORK_DEVICES]));
    expect(ids(await graph(`?vlan=${IPAM_IDS.vlan.v20}`))).toEqual(ids(lab));
    const iot = await graph("?vlan=30");
    expect(ids(iot)).toEqual(sorted([...IOT, ...NETWORK_DEVICES]));
    expect(ids(await graph(`?vlan=${IPAM_IDS.vlan.v30}`))).toEqual(ids(iot));
    expect(ids(await graph("?vlan=30&kind=host"))).toEqual(sorted(IOT));
    // The access points broadcast the VLAN of their SSIDs, the switches carry the VLAN of a port.
    expect(ids(await graph("?vlan=30&kind=access_point"))).toEqual(sorted([T.apHall, T.apGarage]));
    expect(ids(await graph("?vlan=20&kind=switch"))).toEqual([T.swDesk]);
    expect((await graph("?vlan=99")).nodes).toEqual([]);
    // A VLAN id outside 1 to 4094, text, a number too large for a VLAN id.
    for (const vlan of ["0", "4095", "abc", "70000", "-1"]) {
      expectProblem(await get(`${V}/topology?vlan=${vlan}`), 400, "sys.invalid_query");
    }
    const unknown = expectProblem(await get(`${V}/topology?vlan=0190d1c2-0000-7000-8000-000000000001`), 404, "ipam.not_found");
    expect(unknown.params).toMatchObject({ kind: "vlan" });
  });

  it("keep the nodes with an address in a prefix (identifier) or inside a network", async () => {
    expect(ids(await graph(`?prefix=${IPAM_IDS.prefix.iot}&kind=host`))).toEqual([T.sensor]);
    expect(ids(await graph(`?prefix=${IPAM_IDS.prefix.iot}`))).toEqual(sorted([T.sensor, ...NETWORK_DEVICES]));
    // The LAN holds every host with an address but the sensor in the IoT network; the unknown client has none.
    const lan = await graph(`?prefix=${IPAM_IDS.prefix.lan}&kind=host`);
    expect(lan.nodes).toHaveLength(12);
    expect(ids(lan)).not.toContain(T.unknown);
    expect(ids(lan)).not.toContain(T.sensor);
    expect(ids(await graph("?within=198.51.100.0/24&kind=host"))).toEqual([T.sensor]);
    expect(ids(await graph("?within=192.0.2.40/29&kind=host"))).toEqual(sorted([T.thermostat, T.plug, T.camera, T.speaker]));
    // A bare address is a host network; IPv6 works as well.
    expect(ids(await graph("?within=192.0.2.41&kind=host"))).toEqual([T.thermostat]);
    expect(ids(await graph("?within=2001:db8:0:10::/64&kind=router"))).toEqual([T.gateway]);
    // The guests of pve1 hold addresses that intent does not know.
    expect(ids(await graph("?within=192.0.2.150&kind=vm,container"))).toEqual([T.mediaPc]);
    expect((await graph("?within=203.0.113.0/24")).nodes).toEqual([]);
    // Both together, host bits, text and unknown identifiers.
    expectProblem(await get(`${V}/topology?prefix=${IPAM_IDS.prefix.lan}&within=192.0.2.0/24`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology?within=192.0.2.41/24`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology?within=lan`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology?prefix=lan`), 400, "sys.invalid_query");
    const missing = expectProblem(await get(`${V}/topology?prefix=0190d1c2-0000-7000-8000-0000000a0fff`), 404, "ipam.not_found");
    expect(missing.params).toMatchObject({ kind: "prefix" });
  });

  it("keep the kinds named, repeated or separated by commas, and only the edges between them", async () => {
    expect(ids(await graph("?kind=switch&kind=access_point"))).toEqual(sorted([T.swCore, T.swDesk, T.apHall, T.apGarage, T.apAttic]));
    expect(ids(await graph("?kind=switch,router"))).toEqual(sorted([T.gateway, T.swCore, T.swDesk]));
    expect(ids(await graph("?kind=VM"))).toEqual(sorted([T.mediaPc, T.buildVm]));
    const some = await graph("?kind=router,switch");
    expect(some.edges.map((e) => e.kind).sort()).toEqual(["lldp", "uplink"]);
    expect(some.summary).toMatchObject({ nodes: 3, edges: 2, by_kind: { router: 1, switch: 2 }, by_edge_kind: { lldp: 1, uplink: 1 } });
    const guests = await graph("?kind=hypervisor,vm,container");
    expect(guests.nodes).toHaveLength(4);
    expect(guests.edges).toHaveLength(3);
    // No node of the kind `device` in the lab; blank values are dropped.
    expect((await graph("?kind=device")).nodes).toEqual([]);
    expect((await graph("?kind=")).nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
    expect((await graph("?kind=,")).nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
    const bad = expectProblem(await get(`${V}/topology?kind=toaster`), 400, "sys.invalid_query");
    expect(bad.detail).toContain("toaster");
    expectProblem(await get(`${V}/topology?kind=switch,toaster`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology?kind=switch&kind=nope`), 400, "sys.invalid_query");
  });

  it("search the label, MAC and IP addresses, vendor, model and SSIDs", async () => {
    const only = (query: string, kind: string) => graph(`?q=${encodeURIComponent(query)}&kind=${kind}`);
    expect(ids(await only("thermo", "host"))).toEqual([T.thermostat]);
    expect(ids(await only("THERMO", "host"))).toEqual([T.thermostat]);
    expect(ids(await only("00:00:5e:00:53:d2", "host"))).toEqual([T.unknown]);
    expect(ids(await only("53:D2", "host"))).toEqual([T.unknown]);
    expect(ids(await only("192.0.2.150", "vm"))).toEqual([T.mediaPc]);
    expect(ids(await only("example devices", "host"))).toEqual(sorted([T.unknown, T.guestClient]));
    expect(ids(await only("u6-lite", "access_point"))).toEqual(sorted([T.apGarage, T.apAttic]));
    expect(ids(await only("home.example", "access_point"))).toEqual(sorted([T.apHall, T.apAttic]));
    expect(ids(await only("iot.example", "access_point"))).toEqual(sorted([T.apHall, T.apGarage]));
    expect(ids(await only("iot.example", "host"))).toEqual(sorted(IOT));
    expect((await only("no such thing", "host")).nodes).toEqual([]);
    // Blank text keeps everything.
    expect((await graph("?q=")).nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
    expect((await graph("?q=%20%20")).nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
  });

  it("combine with AND", async () => {
    expect(ids(await graph("?kind=host&vlan=30&q=cam"))).toEqual([T.camera]);
    expect(ids(await graph(`?kind=host&vlan=30&site=${IPAM_IDS.site.home}&within=192.0.2.0/24&q=den`))).toEqual([T.speaker]);
    expect((await graph("?kind=host&vlan=20&q=cam")).nodes).toEqual([]);
  });

  it("refuse unknown, repeated and malformed parameters", async () => {
    for (const query of [
      "colour=blue",
      "kind=host&colour=blue",
      "q=a&q=b",
      "site=" + IPAM_IDS.site.home + "&site=" + IPAM_IDS.site.lab,
      "vlan=10&vlan=20",
      "limit=0",
      "limit=20001",
      "limit=-1",
      "limit=many",
      "limit=1&limit=2",
      "at_least=soon",
    ]) {
      expectProblem(await get(`${V}/topology?${query}`), 400, "sys.invalid_query");
    }
    // Paging parameters and a revision to read at are accepted.
    expect((await get(`${V}/topology?limit=20000&at_least=1&cursor=x`)).status).toBe(200);
  });
});

describe("the context of a filter", () => {
  it("adds the network devices next to a kept node and the backbone behind them", async () => {
    const thermostat = await graph("?q=thermostat");
    expect(ids(thermostat)).toEqual(sorted([T.thermostat, ...NETWORK_DEVICES]));
    // The backbone and the client's own edge; nothing else.
    expect(thermostat.summary).toMatchObject({
      nodes: 7,
      edges: 6,
      by_kind: { access_point: 3, host: 1, router: 1, switch: 2 },
      by_edge_kind: { lldp: 1, uplink: 4, wireless: 1 },
    });
    expect(thermostat.edges.some((e) => e.kind === "wireless" && e.a === T.apGarage && e.b === T.thermostat)).toBe(true);
    expect(thermostat.edges.every((e) => ids(thermostat).includes(e.a) && ids(thermostat).includes(e.b))).toBe(true);
  });

  it("adds the hypervisor of a virtual machine and, from it, the network devices", async () => {
    const media = await graph("?q=media");
    expect(ids(media)).toEqual(sorted([T.mediaPc, T.pve1, ...NETWORK_DEVICES]));
    expect(media.summary.by_edge_kind).toEqual({ lldp: 1, uplink: 4, vm_host: 1, wired: 1 });
    // The other guests are no context of their sibling.
    expect(ids(media)).not.toContain(T.buildVm);
  });

  it("keeps the context of a network device whose neighbours are all devices", async () => {
    // A router has no client: its neighbour is sw-core, and the backbone follows.
    expect(ids(await graph("?q=udm-pro"))).toEqual(sorted(NETWORK_DEVICES));
  });

  it("adds nothing when a kind is asked for", async () => {
    const one = await graph("?kind=host&q=thermostat");
    expect(ids(one)).toEqual([T.thermostat]);
    expect(one.edges).toEqual([]);
    expect(one.summary).toMatchObject({ nodes: 1, edges: 0, total_nodes: TOPOLOGY_COUNTS.nodes });
    // A hypervisor and its guests: the edges between them, not the switch behind pve1.
    const pve = await graph("?kind=hypervisor,vm&q=pve1");
    expect(ids(pve)).toEqual([T.pve1]);
  });

  it("counts the VLANs and sites of the answer, not of the whole graph", async () => {
    const lab = await graph("?vlan=20&kind=host");
    expect(lab.summary.vlans).toEqual([
      { vid: 10, vlan: IPAM_IDS.vlan.v10, name: "LAN", nodes: 3 },
      { vid: 20, vlan: IPAM_IDS.vlan.v20, name: "Lab", nodes: 3 },
    ]);
    expect(lab.summary.sites).toEqual([IPAM_IDS.site.home]);
    expect(lab.summary.total_nodes).toBe(TOPOLOGY_COUNTS.nodes);
  });
});

describe("the limit", () => {
  it("cuts the answer and keeps the network devices first", async () => {
    const infrastructure = sorted(NETWORK_DEVICES);
    const three = await graph("?limit=3");
    expect(ids(three)).toEqual(infrastructure.slice(0, 3));
    expect(three.summary).toMatchObject({ nodes: 3, total_nodes: TOPOLOGY_COUNTS.nodes, truncated: true });
    expect(three.edges.every((e) => ids(three).includes(e.a) && ids(three).includes(e.b))).toBe(true);
    const six = await graph("?limit=6");
    expect(ids(six)).toEqual(infrastructure);
    expect(six.summary.truncated).toBe(true);
    expect(six.summary.edges).toBe(5);
    // After the devices, the other nodes follow by identifier.
    const rest = sorted(ids(await graph())).filter((id) => !NETWORK_DEVICES.includes(id));
    expect(ids(await graph("?limit=8"))).toEqual(sorted([...infrastructure, ...rest.slice(0, 2)]));
  });

  it("does not cut an answer that fits", async () => {
    expect((await graph(`?limit=${TOPOLOGY_COUNTS.nodes}`)).summary).toMatchObject({ nodes: TOPOLOGY_COUNTS.nodes, truncated: false });
    expect((await graph(`?limit=${TOPOLOGY_COUNTS.nodes - 1}`)).summary).toMatchObject({ nodes: TOPOLOGY_COUNTS.nodes - 1, truncated: true });
    expect((await graph()).summary.truncated).toBe(false);
    expect((await graph("?limit=20000")).nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
  });

  it("cuts a filtered answer after the context was added", async () => {
    const cut = await graph("?vlan=30&limit=4");
    expect(cut.nodes).toHaveLength(4);
    expect(cut.summary.truncated).toBe(true);
    expect(cut.nodes.every((n) => NETWORK_DEVICES.includes(n.id))).toBe(true);
  });
});

describe("GET /topology/nodes/{id}", () => {
  const node = async (id: string, query = ""): Promise<NodeView> => {
    const answer = await get<NodeView>(`${V}/topology/nodes/${id}${query}`);
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
    return answer.body;
  };

  it("answers the ports of a switch: the controller's table and what hangs on each port", async () => {
    const view = await node(T.swCore);
    expect(view.node).toMatchObject({ id: T.swCore, kind: "switch", label: "sw-core" });
    expect(view.revision).toBe(db.revision);
    expect(view.ports.map((p) => p.port)).toEqual(["1", "2", "3", "4", "5", "6", "7", "8"]);
    expect(view.ports[0]).toMatchObject({ port: "1", name: "Port 1", uplink: true, native_vlan: 10, up: true });
    expect(view.ports[0]?.neighbours).toEqual([
      { node: T.gateway, label: "gw", kind: "router", edge: expect.stringMatching(/^e-/) as string, edge_kind: "uplink", inferred: false, port: "1", remote_port: "1" },
    ]);
    const hanging = Object.fromEntries(view.ports.map((p) => [p.port, p.neighbours.map((n) => [n.label, n.edge_kind, n.vlan ?? null])]));
    expect(hanging).toEqual({
      "1": [["gw", "uplink", null]],
      "2": [["pve1", "wired", 10]],
      "3": [["nas", "wired", 10]],
      "4": [["ha", "wired", 10]],
      "5": [["printer-1", "wired", 10]],
      "6": [["sw-desk", "lldp", null]],
      "7": [["ap-hall", "uplink", null]],
      "8": [],
    });
    expect(view.ports[5]?.neighbours[0]).toMatchObject({ port: "6", remote_port: "1" });
    expect(view.ports[7]).toMatchObject({ port: "8", up: false, uplink: false, neighbours: [] });
    // The neighbours across every edge, ordered by port.
    expect(view.neighbours.map((n) => [n.port, n.label])).toEqual([
      ["1", "gw"],
      ["2", "pve1"],
      ["3", "nas"],
      ["4", "ha"],
      ["5", "printer-1"],
      ["6", "sw-desk"],
      ["7", "ap-hall"],
    ]);
  });

  it("keeps one port, matched by the port or the controller's name", async () => {
    for (const port of ["3", "Port%203"]) {
      const view = await node(T.swCore, `?port=${port}`);
      expect(view.ports).toHaveLength(1);
      expect(view.ports[0]).toMatchObject({ port: "3", name: "Port 3" });
      expect(view.ports[0]?.neighbours.map((n) => n.node)).toEqual([T.nas]);
      // The neighbours of the node stay whole.
      expect(view.neighbours).toHaveLength(7);
    }
    expect((await node(T.swCore, "?port=9")).ports).toEqual([]);
    expect((await node(T.swCore, "?port=")).ports).toHaveLength(8);
    // A client names no port of its own.
    const nas = await node(T.nas, "?port=3");
    expect(nas.ports.map((p) => p.port)).toEqual([]);
  });

  it("names the neighbours of an access point across wireless edges and its uplink", async () => {
    const view = await node(T.apHall);
    expect(view.ports).toEqual([]);
    expect(view.neighbours.map((n) => [n.label, n.edge_kind, n.ssid ?? null, n.vlan ?? null, n.remote_port ?? null])).toEqual([
      ["cam-door", "wireless", TOPOLOGY_SSIDS.iot, 30, null],
      ["plug-kitchen", "wireless", TOPOLOGY_SSIDS.iot, 30, null],
      ["speaker-den", "wireless", TOPOLOGY_SSIDS.iot, 30, null],
      ["sw-core", "uplink", null, null, "7"],
      ["tv-living", "wireless", TOPOLOGY_SSIDS.home, 10, null],
    ]);
    // The ports of the gateway: the table lists both, the second is the uplink to the provider.
    const gw = await node(T.gateway);
    expect(gw.ports.map((p) => [p.port, p.uplink, p.neighbours.length])).toEqual([
      ["1", false, 1],
      ["2", true, 0],
    ]);
  });

  it("names the guests of a hypervisor and the hypervisor of a guest", async () => {
    const pve = await node(T.pve1);
    // No port on this side of any edge: ordered by label.
    expect(pve.neighbours.map((n) => [n.label, n.edge_kind])).toEqual([
      ["build-vm", "vm_host"],
      ["dns-ct", "vm_host"],
      ["media-pc", "vm_host"],
      ["sw-core", "wired"],
    ]);
    expect(pve.ports.map((p) => p.port)).toEqual([]);
    expect((await node(T.mediaPc)).neighbours).toMatchObject([{ node: T.pve1, edge_kind: "vm_host" }]);
  });

  it("answers the host of intent with its live addresses, network and VLAN", async () => {
    const printer = await node(T.printer);
    expect(printer.intent).toEqual({
      host: HOST_IDS["printer-1"],
      name: "printer-1",
      mode: "static",
      addresses: [{ ip: "192.0.2.30", prefix: IPAM_IDS.prefix.lan, cidr: "192.0.2.0/24", vlan: IPAM_IDS.vlan.v10, vid: 10 }],
    });
    // IPv4 first, then IPv6.
    const gw = await node(T.gateway);
    expect(gw.intent?.addresses).toEqual([
      { ip: "192.0.2.1", prefix: IPAM_IDS.prefix.lan, cidr: "192.0.2.0/24", vlan: IPAM_IDS.vlan.v10, vid: 10 },
      { ip: "2001:db8:0:10::1", prefix: IPAM_IDS.prefix.lanV6, cidr: "2001:db8:0:10::/64", vlan: IPAM_IDS.vlan.v10, vid: 10 },
    ]);
    // A node without a host has no intent.
    for (const id of [T.unknown, T.apAttic, T.mediaPc]) expect((await node(id)).intent ?? null, id).toBeNull();
    expect((await node(T.unknown)).node.vendor).toBe("Example Devices");
  });

  it("reads the intent live", async () => {
    const id = HOST_IDS.nas as string;
    applyCommands([{ op: "update_host", args: { id, expected: null, patch: { name: "nas-main" } } }] as never);
    const renamed = await node(T.nas);
    expect(renamed.intent).toMatchObject({ name: "nas-main", mode: "reserved" });
    // The nodes of the graph are as the sources observed them.
    expect(renamed.node.label).toBe("nas");
  });

  it("drops the intent of a host that was deleted", async () => {
    const id = HOST_IDS["ha"] as string;
    applyCommands([{ op: "delete", args: { object: { kind: "host", id }, expected: null, cascade: true } }] as never);
    const view = await node(T.ha);
    expect(view.intent ?? null).toBeNull();
    expect(view.node.host).toBe(id);
  });

  it("answers 404 for an unknown node and 400 for bad parameters", async () => {
    const missing = expectProblem(await get(`${V}/topology/nodes/m-000000000000`), 404, "ipam.topology.not_found");
    expect(missing.params).toEqual({ id: "m-000000000000" });
    expectProblem(await get(`${V}/topology/nodes/${T.swCore}?colour=blue`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology/nodes/${T.swCore}?port=1&port=2`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/topology/nodes/${T.swCore}?at_least=soon`), 400, "sys.invalid_query");
    expect((await get(`${V}/topology/nodes/${T.swCore}?at_least=1`)).status).toBe(200);
  });
});

describe("the network controller", () => {
  it("is listed with its networks while it is configured and enabled", async () => {
    mockVlanController.enabled = false;
    expect((await graph()).summary).toMatchObject({ controllers: [], networks: [] });
    mockVlanController.enabled = true;
    mockVlanController.present = false;
    const removed = await graph();
    expect(removed.summary).toMatchObject({ controllers: [], networks: [] });
    // The graph itself is what the sources observed.
    expect(removed.nodes).toHaveLength(TOPOLOGY_COUNTS.nodes);
  });

  it("shows the networks it has now and is restored by a reset", async () => {
    mockVlanController.networks.push({ id: "net-guest", name: "Guest", vlan: 50, management: false });
    mockVlanController.writes_enabled = false;
    expect((await graph()).summary.networks.map((n) => [n.vlan, n.name])).toEqual([
      [10, "Management"],
      [30, "IoT"],
      [50, "Guest"],
    ]);
    const same = mockVlanController;
    resetMockDb("signed-in");
    expect(mockVlanController).toBe(same);
    expect(mockVlanController).toMatchObject({ present: true, enabled: true, writes_enabled: true, id: T.controller });
    expect((await graph()).summary.networks).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------------
// The inferred edges, the controller's write flag and the root

describe("the inferred edges", () => {
  it("mark a client edge no network controller reports, and only that", async () => {
    const g = await graph();
    const inferred = g.edges.filter((e) => e.inferred);
    expect(inferred.map((e) => [e.kind, e.b])).toEqual([["wired", T.printer]]);
    expect(inferred[0]?.sources.every((s) => !s.startsWith("network_controller:"))).toBe(true);
    // Every edge carries the flag; links between devices and placements are never inferred.
    expect(g.edges.every((e) => typeof e.inferred === "boolean")).toBe(true);
    expect(g.edges.filter((e) => e.kind !== "wired" && e.kind !== "wireless").some((e) => e.inferred)).toBe(false);
    // An edge the controller reports stays certain although a probe saw it too.
    expect(g.edges.find((e) => e.kind === "wired" && e.b === T.nas)).toMatchObject({ inferred: false });
  });

  it("reach the neighbours of the node view", async () => {
    const view = (await get<NodeView>(`${V}/topology/nodes/${T.swCore}`)).body;
    const byLabel = new Map(view.neighbours.map((n) => [n.label, n.inferred] as const));
    expect(byLabel.get("printer-1")).toBe(true);
    expect(byLabel.get("nas")).toBe(false);
    expect(byLabel.get("gw")).toBe(false);
  });
});

describe("the controllers of the summary", () => {
  it("carry whether writes through them are allowed", async () => {
    expect((await graph()).summary.controllers[0]?.writes_enabled).toBe(true);
    mockVlanController.writes_enabled = false;
    expect((await graph()).summary.controllers[0]?.writes_enabled).toBe(false);
  });
});

describe("the root of the map", () => {
  const rootAnswer = () => get<S["RootDecision"]>(`${V}/topology/root`);
  const chosen = (source: string, headers?: Record<string, string>) => send<S["RootDecision"]>("PUT", `${V}/topology/root`, { source }, headers);
  const findingsOf = async (kind: string): Promise<S["Finding"][]> =>
    (await get<{ items: S["Finding"][] }>(`${V}/findings?kind=${kind}`)).body.items;
  const SW_CORE_IP = "192.0.2.2";

  it("is the gateway the controller reports while both sources agree", async () => {
    const { body, status } = await rootAnswer();
    expect(status).toBe(200);
    expect(body.candidates.map((c) => [c.source, c.node, c.label, c.ip])).toEqual([
      ["controller", T.gateway, "gw", "192.0.2.1"],
      ["default_route", T.gateway, "gw", "192.0.2.1"],
    ]);
    expect(body).toMatchObject({ disagree: false, open: false, root: { source: "controller", node: T.gateway, chosen: false }, revision: db.revision });
    expect(body.choice).toBeUndefined();
    expect((await graph()).summary.root).toEqual({ source: "controller", node: T.gateway, chosen: false });
    expect(await findingsOf("topology_root")).toEqual([]);
  });

  it("raises one finding to review when the sources disagree, with the labels and addresses as parameters", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    const { body } = await rootAnswer();
    expect(body).toMatchObject({ disagree: true, open: true, root: { source: "controller", node: T.gateway, chosen: false } });
    expect(body.candidates[1]).toMatchObject({ source: "default_route", node: T.swCore, label: "sw-core", ip: SW_CORE_IP });
    const [finding, ...rest] = await findingsOf("topology_root");
    expect(rest).toEqual([]);
    expect(finding).toMatchObject({
      severity: "review",
      area: "topology",
      source: "topology",
      action: "use_root",
      code: "ipam.topology.root_disagree",
      evidence: { id: "root", path: "/topology/root" },
      subject: { kind: "node", label: "gw / sw-core" },
      params: {
        controller_label: "gw",
        controller_node: T.gateway,
        controller_ip: "192.0.2.1",
        default_route_label: "sw-core",
        default_route_node: T.swCore,
        default_route_ip: SW_CORE_IP,
      },
    });
    expect(finding?.id).toMatch(/^topology:root:[0-9a-f]{32}$/);
  });

  it("follows the chosen source, stores the candidates on offer and clears the finding", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    const before = await findingsOf("topology_root");
    const answer = await chosen("default_route");
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({ disagree: true, open: false, root: { source: "default_route", node: T.swCore, chosen: true } });
    expect(answer.body.choice).toMatchObject({ source: "default_route", offered: [`controller:${T.gateway}`, `route:${SW_CORE_IP}`] });
    expect(answer.body.choice?.revision).toBeGreaterThan(0);
    expect(answer.body.choice?.decided.by.kind).toBe("user");
    expect((await graph()).summary.root).toEqual({ source: "default_route", node: T.swCore, chosen: true });
    expect(await findingsOf("topology_root")).toEqual([]);
    expect(before).toHaveLength(1);
    // The read answers the stored choice with its ETag.
    const read = await rootAnswer();
    expect(read.res.headers.get("etag")).toBe(`"${answer.body.choice?.revision}"`);
    expect(read.body.choice).toEqual(answer.body.choice);
    // A choice of the other source replaces it.
    expect((await chosen("controller")).body).toMatchObject({ root: { source: "controller", node: T.gateway, chosen: true }, open: false });
  });

  it("opens the finding again when the candidates on offer change, and when the choice is cleared", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    await chosen("controller");
    expect((await rootAnswer()).body.open).toBe(false);
    topologyState().nextHops = ["192.0.2.3"];
    const changed = (await rootAnswer()).body;
    expect(changed).toMatchObject({ disagree: true, open: true, root: { source: "controller", chosen: true } });
    expect(await findingsOf("topology_root")).toHaveLength(1);
    // Choosing again records the new candidates.
    await chosen("controller");
    expect((await rootAnswer()).body.open).toBe(false);
    // Forgetting the choice lets the ranked source decide and raises the finding again.
    const cleared = await send("DELETE", `${V}/topology/root`);
    expect(cleared.status).toBe(204);
    expect((await rootAnswer()).body).toMatchObject({ open: true, root: { source: "controller", chosen: false } });
    expect((await rootAnswer()).body.choice).toBeUndefined();
    expect(await findingsOf("topology_root")).toHaveLength(1);
  });

  it("closes the finding when the sources agree again, and keeps the choice", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    await chosen("default_route");
    topologyState().nextHops = ["192.0.2.1"];
    expect((await rootAnswer()).body).toMatchObject({ disagree: false, open: false, choice: { source: "default_route" } });
    expect(await findingsOf("topology_root")).toEqual([]);
  });

  it("names a next hop no node holds by its address, and never an access point", async () => {
    topologyState().nextHops = ["192.0.2.99"];
    const outside = (await rootAnswer()).body;
    expect(outside.candidates[1]).toEqual({ source: "default_route", label: "192.0.2.99", ip: "192.0.2.99" });
    expect(outside.disagree).toBe(true);
    expect((await chosen("default_route")).body.root).toEqual({ source: "default_route", chosen: true });
    expect((await rootAnswer()).body.choice?.offered).toEqual([`controller:${T.gateway}`, "route:192.0.2.99"]);
    // ap-hall holds 192.0.2.4 and is no candidate; the next hop stays an address.
    topologyState().nextHops = ["192.0.2.4"];
    expect((await rootAnswer()).body.candidates[1]).toEqual({ source: "default_route", label: "192.0.2.4", ip: "192.0.2.4" });
    // The first hop a node holds wins over an earlier hop nobody holds.
    topologyState().nextHops = ["192.0.2.99", SW_CORE_IP];
    expect((await rootAnswer()).body.candidates[1]).toMatchObject({ node: T.swCore, ip: SW_CORE_IP });
  });

  it("refuses a source without a candidate with 409 ipam.topology.no_candidate", async () => {
    topologyState().nextHops = [];
    const one = (await rootAnswer()).body;
    expect(one.candidates.map((c) => c.source)).toEqual(["controller"]);
    expect(one).toMatchObject({ disagree: false, open: false });
    const refused = expectProblem(await chosen("default_route"), 409, "ipam.topology.no_candidate");
    expect(refused.params).toEqual({ source: "default_route" });
    expect(mockTopologyDecisions.root).toBeNull();
    // Without a network controller the controller source has none.
    topologyState().nextHops = ["192.0.2.1"];
    mockVlanController.enabled = false;
    expect((await rootAnswer()).body.candidates.map((c) => c.source)).toEqual(["default_route"]);
    expectProblem(await chosen("controller"), 409, "ipam.topology.no_candidate");
  });

  it("answers 404 ipam.topology.not_stored when no root was chosen, and 400 for a bad body", async () => {
    const missing = expectProblem(await send("DELETE", `${V}/topology/root`), 404, "ipam.topology.not_stored");
    expect(missing.params).toEqual({ kind: "root choice" });
    expectProblem(await chosen("sideways"), 400, "sys.invalid_request");
    expectProblem(await send("PUT", `${V}/topology/root`, { source: "controller", extra: 1 }), 400, "sys.invalid_request");
    expectProblem(await send("PUT", `${V}/topology/root`), 400, "sys.invalid_request");
  });

  it("honours If-Match on the stored choice", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    const first = await chosen("controller");
    const revision = first.body.choice?.revision as number;
    expectProblem(await chosen("default_route", { "if-match": `"${revision + 100}"` }), 412, "ipam.revision_mismatch");
    expectProblem(await send("DELETE", `${V}/topology/root`, undefined, { "if-match": `"${revision + 100}"` }), 412, "ipam.revision_mismatch");
    expect((await chosen("default_route", { "if-match": `"${revision}"` })).status).toBe(200);
  });

  it("is written by administrators and operators, read by every account", async () => {
    await signInWithRoles(["viewer"]);
    expect((await rootAnswer()).status).toBe(200);
    expectProblem(await chosen("controller"), 403, "auth.forbidden");
    expectProblem(await send("DELETE", `${V}/topology/root`), 403, "auth.forbidden");
    await signInWithRoles(["operator"]);
    expect((await chosen("controller")).status).toBe(200);
    expect((await send("DELETE", `${V}/topology/root`)).status).toBe(204);
  });

  it("is a reset away from the seed", async () => {
    topologyState().nextHops = [SW_CORE_IP];
    await chosen("controller");
    resetMockDb("signed-in");
    expect((await rootAnswer()).body).toMatchObject({ disagree: false, open: false });
    expect((await rootAnswer()).body.choice).toBeUndefined();
  });

  it("has no root while the graph is empty", async () => {
    Object.assign(topologyState(), { nodes: [], edges: [], wireless: [], nextHops: [] });
    const body = (await rootAnswer()).body;
    expect(body).toMatchObject({ candidates: [], disagree: false, open: false });
    expect(body.root).toBeUndefined();
    expect((await graph()).summary.root).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------------
// The SSID view, the policies and the two WLAN rules

describe("the SSID view and the WLAN rules", () => {
  const HOME = TOPOLOGY_SSIDS.home;
  const IOT_SSID = TOPOLOGY_SSIDS.iot;
  const GUEST = TOPOLOGY_SSIDS.guest;
  const ssidPath = (ssid: string) => encodeURIComponent(ssid);
  const view = async (): Promise<S["SsidView"]> => {
    const answer = await get<S["SsidView"]>(`${V}/topology/ssids`);
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
    return answer.body;
  };
  const entry = async (ssid: string): Promise<S["SsidEntry"]> => {
    const found = (await view()).ssids.find((s) => s.ssid === ssid);
    expect(found, ssid).toBeDefined();
    return found as S["SsidEntry"];
  };
  const clientsOf = (e: S["SsidEntry"]): S["SsidClient"][] => e.vlans.flatMap((v) => v.clients);
  const topology = async (): Promise<S["Finding"][]> => (await get<{ items: S["Finding"][] }>(`${V}/findings?source=topology`)).body.items;
  const tag = (name: string, tags: string[]) => {
    const id = HOST_IDS[name] as string;
    applyCommands([{ op: "update_host", args: { id, patch: { tags } } }] as never);
    return id;
  };
  const policy = (ssid: string, value: string) => send<S["StoredWlanPolicy"]>("PUT", `${V}/topology/ssids/${ssidPath(ssid)}/policy`, { policy: value });
  const keep = (ssid: string, name: string, json?: unknown) => send<S["WlanException"]>("PUT", `${V}/topology/ssids/${ssidPath(ssid)}/exceptions/${HOST_IDS[name]}`, json);
  const tv = () => topologyState().wireless.find((c) => c.node === T.tv) as { ip?: string };

  it("is a tree of SSIDs, VLANs and clients with the access point and the band as attributes", async () => {
    const { ssids, revision } = await view();
    expect(revision).toBe(db.revision);
    expect(ssids.map((s) => s.ssid)).toEqual([GUEST, HOME, IOT_SSID]);

    const iot = ssids.find((s) => s.ssid === IOT_SSID) as S["SsidEntry"];
    expect(iot).toMatchObject({
      vid: 30,
      guest: false,
      enabled: true,
      policy: "track",
      policy_set: false,
      connectors: [T.controller],
      access_points: ["ap-garage", "ap-hall"],
      clients: 5,
      findings: 0,
    });
    expect(iot.vlans).toHaveLength(1);
    expect(iot.vlans[0]).toMatchObject({ vid: 30, vlan: IPAM_IDS.vlan.v30, name: "IoT", iot: false });
    expect((iot.vlans[0]?.prefixes ?? []).map((p) => p.cidr).sort()).toEqual(["198.51.100.0/24", "2001:db8:0:30::/64"].sort());
    expect(clientsOf(iot).map((c) => [c.label, c.band, c.access_point])).toEqual([
      ["cam-door", "5g", "ap-hall"],
      ["plug-kitchen", "2g", "ap-hall"],
      ["sensor-garage", "2g", "ap-garage"],
      ["speaker-den", "5g", "ap-hall"],
      ["thermostat-1", "2g", "ap-garage"],
    ]);
    const plug = clientsOf(iot).find((c) => c.label === "plug-kitchen") as S["SsidClient"];
    expect(plug).toMatchObject({
      mac: "00:00:5e:00:53:2a",
      ip: "198.51.100.42",
      node: T.plug,
      host: HOST_IDS["plug-kitchen"],
      access_point_node: T.apHall,
      iot: false,
      kept: false,
    });

    const home = ssids.find((s) => s.ssid === HOME) as S["SsidEntry"];
    expect(home).toMatchObject({ vid: 10, policy: "track", access_points: ["ap-attic", "ap-hall"], clients: 1, findings: 1 });
    expect(home.vlans[0]).toMatchObject({ vid: 10, name: "LAN", iot: false });
    expect(clientsOf(home)).toEqual([
      expect.objectContaining({
        label: "tv-living",
        band: "6g",
        host: HOST_IDS["tv-living"],
        iot: true,
        access_point: "ap-hall",
        access_point_node: T.apHall,
        findings: ["wlan_class"],
        kept: false,
      }),
    ]);

    // The guest network: ignored by default, one client without a host, known by vendor.
    const guest = ssids.find((s) => s.ssid === GUEST) as S["SsidEntry"];
    expect(guest).toMatchObject({ vid: 40, guest: true, policy: "ignore", policy_set: false, clients: 1, findings: 0, access_points: ["ap-attic"] });
    expect(guest.vlans[0]).toMatchObject({ vid: 40, name: "DMZ" });
    expect(clientsOf(guest)).toEqual([
      expect.objectContaining({
        label: "Example Devices 00:53:d3",
        band: "5g",
        node: T.guestClient,
        vendor: "Example Devices",
        access_point: "ap-attic",
        access_point_node: T.apAttic,
        ip: "203.0.113.130",
        iot: false,
      }),
    ]);
    expect(clientsOf(guest)[0]?.host).toBeUndefined();
    // The three bands appear in the lab.
    expect(new Set(ssids.flatMap(clientsOf).map((c) => c.band))).toEqual(new Set(["2g", "5g", "6g"]));
  });

  it("lists no SSID without a network controller or while the graph is empty", async () => {
    mockVlanController.enabled = false;
    expect((await view()).ssids).toEqual([]);
    expect(await topology()).toEqual([]);
    mockVlanController.enabled = true;
    Object.assign(topologyState(), { nodes: [], edges: [], wireless: [] });
    expect((await view()).ssids).toEqual([]);
  });

  it("raises exactly one wlan_class finding by default: the IoT-classed host on the home WLAN", async () => {
    const [finding, ...rest] = await topology();
    expect(rest).toEqual([]);
    expect(finding).toMatchObject({
      kind: "wlan_class",
      severity: "review",
      area: "topology",
      source: "topology",
      action: "move_host",
      code: "ipam.topology.wlan_class",
      summary: "tv-living is classed as IoT and is on the WLAN home.example.test (VLAN 10), which is not an IoT network",
      evidence: { id: `${HOST_IDS["tv-living"]}/${HOME}`, path: "/topology/ssids" },
      subject: { kind: "host", label: "tv-living", host: HOST_IDS["tv-living"], mac: "00:00:5e:00:53:39", ip: "192.0.2.57", prefix: IPAM_IDS.prefix.lan },
      params: {
        host: "tv-living",
        ssid: HOME,
        mac: "00:00:5e:00:53:39",
        class: "iot",
        role: "other",
        access_point: "ap-hall",
        vlan: "10",
        vlan_name: "LAN",
        ip: "192.0.2.57",
        band: "6g",
      },
    });
    expect(finding?.id).toMatch(/^topology:wlan:[0-9a-f]{32}$/);
    expect(finding?.subject.objects).toEqual([{ kind: "host", id: HOST_IDS["tv-living"] }]);
    expect(finding?.params?.prefix).toContain("192.0.2.0/24");
  });

  it("class rule: the IoT role of the VLAN or of one of its networks clears the finding", async () => {
    applyCommands([{ op: "update_vlan", args: { id: IPAM_IDS.vlan.v10, patch: { tags: ["role:iot"] } } }] as never);
    expect(await topology()).toEqual([]);
    expect((await entry(HOME)).vlans[0]?.iot).toBe(true);
    applyCommands([{ op: "update_vlan", args: { id: IPAM_IDS.vlan.v10, patch: { tags: [] } } }] as never);
    expect(await topology()).toHaveLength(1);
    applyCommands([{ op: "update_prefix", args: { id: IPAM_IDS.prefix.lan, patch: { tags: ["role:iot"] } } }] as never);
    expect(await topology()).toEqual([]);
    expect((await entry(HOME)).vlans[0]?.iot).toBe(true);
  });

  it("class rule: a host tagged class:iot on a WLAN without the role raises one, an unclassed host none", async () => {
    tag("plug-kitchen", ["iot", "class:iot"]);
    const findings = await topology();
    expect(findings.map((f) => [f.kind, f.subject.label]).sort()).toEqual([
      ["wlan_class", "plug-kitchen"],
      ["wlan_class", "tv-living"],
    ]);
    const iot = await entry(IOT_SSID);
    expect(clientsOf(iot).find((c) => c.label === "plug-kitchen")).toMatchObject({ iot: true, findings: ["wlan_class"] });
    expect(iot.findings).toBe(1);
    // The IoT role on the IoT network is what such a host belongs on.
    applyCommands([{ op: "update_prefix", args: { id: IPAM_IDS.prefix.iot, patch: { tags: ["role:iot"] } } }] as never);
    expect((await topology()).map((f) => f.subject.label)).toEqual(["tv-living"]);
    expect((await entry(IOT_SSID)).vlans[0]).toMatchObject({ iot: true });
    // Without the classification the TV is no IoT device either.
    mockTopologyDecisions.iotHosts.clear();
    expect(await topology()).toEqual([]);
  });

  it("prefix rule: an address outside the networks of the VLAN, of the same family", async () => {
    // Inside the network: nothing besides the class finding.
    expect((await topology()).map((f) => f.kind)).toEqual(["wlan_class"]);
    // An IPv4 address outside 192.0.2.0/24.
    tv().ip = "198.51.100.57";
    const findings = await topology();
    expect(findings.map((f) => f.kind).sort()).toEqual(["wlan_class", "wlan_prefix"]);
    const prefix = findings.find((f) => f.kind === "wlan_prefix") as S["Finding"];
    expect(prefix).toMatchObject({
      severity: "review",
      action: "move_host",
      code: "ipam.topology.wlan_prefix",
      subject: { kind: "host", label: "tv-living", ip: "198.51.100.57", prefix: IPAM_IDS.prefix.iot },
      params: { host: "tv-living", ssid: HOME, ip: "198.51.100.57", vlan: "10", class: "iot" },
    });
    expect(prefix.params?.prefix).toContain("192.0.2.0/24");
    expect(prefix.summary).toMatch(/^tv-living has the address 198\.51\.100\.57 on the WLAN home\.example\.test, outside .*192\.0\.2\.0\/24.* of VLAN 10$/);
    expect(clientsOf(await entry(HOME))[0]?.findings).toEqual(["wlan_class", "wlan_prefix"]);
    // An IPv6 address inside the IPv6 network is fine, outside it is not.
    tv().ip = "2001:db8:0:10::5";
    expect((await topology()).map((f) => f.kind)).toEqual(["wlan_class"]);
    tv().ip = "2001:db8:ffff::5";
    expect((await topology()).map((f) => f.kind).sort()).toEqual(["wlan_class", "wlan_prefix"]);
    // No address, no judgement.
    delete tv().ip;
    expect((await topology()).map((f) => f.kind)).toEqual(["wlan_class"]);
  });

  it("prefix rule: a VLAN without networks of the family is not judged, and the class tag is not needed", async () => {
    mockTopologyDecisions.iotHosts.clear();
    // The LAN has an IPv4 and an IPv6 network; remove the IPv6 one: an IPv6 address has nothing to be outside of.
    applyCommands([{ op: "delete", args: { object: { kind: "prefix", id: IPAM_IDS.prefix.lanV6 }, cascade: true } }] as never);
    tv().ip = "2001:db8:ffff::5";
    expect(await topology()).toEqual([]);
    tv().ip = "198.51.100.57";
    const [finding, ...rest] = await topology();
    expect(rest).toEqual([]);
    expect(finding?.kind).toBe("wlan_prefix");
    expect(finding?.params?.class).toBeUndefined();
  });

  it("skips unmanaged and decommissioned hosts, clients without a host and deleted hosts", async () => {
    expect(await topology()).toHaveLength(1);
    const id = HOST_IDS["tv-living"] as string;
    applyCommands([{ op: "update_host", args: { id, patch: { mode: "unmanaged" } } }] as never);
    expect(await topology()).toEqual([]);
    applyCommands([{ op: "update_host", args: { id, patch: { mode: "dynamic" } } }] as never);
    expect(await topology()).toHaveLength(1);
    expect((await send("POST", `${V}/hosts/${id}/decommission`, {})).status).toBe(200);
    expect(await topology()).toEqual([]);
    expect(clientsOf(await entry(HOME))[0]).toMatchObject({ label: "tv-living", findings: [] });
    // The guest client has no host: tracking its SSID raises nothing.
    expect((await policy(GUEST, "track")).status).toBe(200);
    expect(await topology()).toEqual([]);
    // A host that is deleted is no host any more: the client is named by the controller.
    resetMockDb("signed-in");
    applyCommands([{ op: "delete", args: { object: { kind: "host", id }, cascade: true } }] as never);
    expect(await topology()).toEqual([]);
    expect(clientsOf(await entry(HOME)).find((c) => c.node === T.tv)?.host).toBeUndefined();
  });

  it("an ignored SSID raises none, and the default of a guest SSID is ignore", async () => {
    tag("plug-kitchen", ["class:iot"]);
    expect(await topology()).toHaveLength(2);
    const set = await policy(IOT_SSID, "ignore");
    expect(set.status).toBe(200);
    expect(set.body).toMatchObject({ ssid: IOT_SSID, policy: "ignore" });
    expect(set.body.revision).toBeGreaterThan(0);
    expect(set.res.headers.get("etag")).toBe(`"${set.body.revision}"`);
    expect((await topology()).map((f) => f.subject.label)).toEqual(["tv-living"]);
    expect(await entry(IOT_SSID)).toMatchObject({ policy: "ignore", policy_set: true, findings: 0 });
    // Tracking the home WLAN explicitly changes nothing but `policy_set`.
    await policy(HOME, "track");
    expect(await entry(HOME)).toMatchObject({ policy: "track", policy_set: true, findings: 1 });
    // The guest network is ignored until a person tracks it, and is ignored again after the delete.
    await policy(GUEST, "track");
    expect(await entry(GUEST)).toMatchObject({ policy: "track", policy_set: true });
    expect((await send("DELETE", `${V}/topology/ssids/${ssidPath(GUEST)}/policy`)).status).toBe(204);
    expect(await entry(GUEST)).toMatchObject({ policy: "ignore", policy_set: false });
    // Removing the policy of the IoT SSID brings the rule back.
    expect((await send("DELETE", `${V}/topology/ssids/${ssidPath(IOT_SSID)}/policy`)).status).toBe(204);
    expect(await topology()).toHaveLength(2);
    expect(mockTopologyDecisions.policies.has(IOT_SSID)).toBe(false);
  });

  it("keeps a host on one WLAN: the finding of that pair goes away and no other", async () => {
    tag("plug-kitchen", ["class:iot"]);
    tag("thermostat-1", ["class:iot"]);
    expect(await topology()).toHaveLength(3);
    const kept = await keep(HOME, "tv-living", { reason: "  The TV is a media device  " });
    expect(kept.status).toBe(200);
    expect(kept.body).toMatchObject({ host: HOST_IDS["tv-living"], ssid: HOME, reason: "The TV is a media device" });
    expect(kept.res.headers.get("etag")).toBe(`"${kept.body.revision}"`);
    expect((await topology()).map((f) => f.subject.label).sort()).toEqual(["plug-kitchen", "thermostat-1"]);
    expect(clientsOf(await entry(HOME))[0]).toMatchObject({ kept: true, findings: [] });
    // Another host on another SSID is judged as before (the pair is the key).
    const other = await keep(IOT_SSID, "plug-kitchen");
    expect(other.body.reason).toBeUndefined();
    expect((await topology()).map((f) => f.subject.label)).toEqual(["thermostat-1"]);
    expect(clientsOf(await entry(IOT_SSID)).find((c) => c.label === "plug-kitchen")).toMatchObject({ kept: true, findings: [] });
    expect(clientsOf(await entry(IOT_SSID)).find((c) => c.label === "thermostat-1")).toMatchObject({ kept: false, findings: ["wlan_class"] });
    // Keeping again with the same reason changes nothing; a new reason is a new decision.
    const revision = db.revision;
    expect((await keep(HOME, "tv-living", { reason: "The TV is a media device" })).body.revision).toBe(kept.body.revision);
    expect(db.revision).toBe(revision);
    expect((await keep(HOME, "tv-living", { reason: "Moved to the media room" })).body.revision).toBeGreaterThan(kept.body.revision ?? 0);
    // Removing an exception brings the finding back.
    expect((await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/${HOST_IDS["tv-living"]}`)).status).toBe(204);
    expect((await topology()).map((f) => f.subject.label).sort()).toEqual(["thermostat-1", "tv-living"]);
    const gone = expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/${HOST_IDS["tv-living"]}`), 404, "ipam.topology.not_stored");
    expect(gone.params).toEqual({ kind: "WLAN exception" });
  });

  it("refuses bad SSIDs, hosts and reasons with the codes of the server", async () => {
    const long = "x".repeat(33);
    const tooLong = expectProblem(await policy(long, "track"), 422, "ipam.topology.invalid");
    expect(tooLong.params).toEqual({ field: "ssid" });
    expect((await policy("x".repeat(32), "track")).status).toBe(200);
    // Multi-byte characters count as octets: 17 two-byte letters are 34 octets.
    expectProblem(await policy("é".repeat(17), "track"), 422, "ipam.topology.invalid");
    expect((await policy("é".repeat(16), "track")).status).toBe(200);
    expectProblem(await send("PUT", `${V}/topology/ssids/bad%07name/policy`, { policy: "track" }), 422, "ipam.topology.invalid");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${long}/policy`), 422, "ipam.topology.invalid");
    expectProblem(await keep(long, "tv-living"), 422, "ipam.topology.invalid");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${long}/exceptions/${HOST_IDS["tv-living"]}`), 422, "ipam.topology.invalid");
    // The reason: at most 1,024 octets, no control characters other than line breaks and tabs.
    expectProblem(await keep(HOME, "tv-living", { reason: "r".repeat(1025) }), 422, "ipam.topology.invalid");
    expectProblem(await keep(HOME, "tv-living", { reason: "bell\u0007" }), 422, "ipam.topology.invalid");
    expect((await keep(HOME, "tv-living", { reason: "two\nlines\tand a tab" })).status).toBe(200);
    // An unknown host, a host that is deleted, a malformed identifier and a malformed body.
    expectProblem(await send("PUT", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/0190d1c2-0000-7000-8000-0000000b0fff`), 404, "ipam.not_found");
    const id = HOST_IDS["ha"] as string;
    applyCommands([{ op: "delete", args: { object: { kind: "host", id }, cascade: true } }] as never);
    expect(expectProblem(await keep(HOME, "ha"), 404, "ipam.not_found").params).toMatchObject({ kind: "host", id });
    expectProblem(await send("PUT", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/not-a-host`), 400, "sys.invalid_request");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/not-a-host`), 400, "sys.invalid_request");
    expectProblem(await keep(HOME, "tv-living", { reason: 7 }), 400, "sys.invalid_request");
    expectProblem(await keep(HOME, "tv-living", { why: "x" }), 400, "sys.invalid_request");
    expectProblem(await policy(HOME, "sometimes"), 400, "sys.invalid_request");
    expectProblem(await send("PUT", `${V}/topology/ssids/${ssidPath(HOME)}/policy`, {}), 400, "sys.invalid_request");
    // Nothing stored: 404 ipam.topology.not_stored.
    expect(expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/policy`), 404, "ipam.topology.not_stored").params).toEqual({ kind: "WLAN policy" });
  });

  it("encodes an SSID with spaces and non-ASCII letters in the path", async () => {
    const name = "Café WLAN 2.4";
    const set = await policy(name, "ignore");
    expect(set.body.ssid).toBe(name);
    expect(mockTopologyDecisions.policies.get(name)?.policy).toBe("ignore");
    expect((await send("DELETE", `${V}/topology/ssids/${ssidPath(name)}/policy`)).status).toBe(204);
  });

  it("honours If-Match on a stored policy and exception", async () => {
    const first = await policy(HOME, "ignore");
    const revision = first.body.revision as number;
    expectProblem(await send("PUT", `${V}/topology/ssids/${ssidPath(HOME)}/policy`, { policy: "track" }, { "if-match": `"${revision + 9}"` }), 412, "ipam.revision_mismatch");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/policy`, undefined, { "if-match": `"${revision + 9}"` }), 412, "ipam.revision_mismatch");
    expect((await send("PUT", `${V}/topology/ssids/${ssidPath(HOME)}/policy`, { policy: "track" }, { "if-match": `"${revision}"` })).status).toBe(200);
    const kept = await keep(HOME, "tv-living");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/${HOST_IDS["tv-living"]}`, undefined, { "if-match": `"${(kept.body.revision as number) + 9}"` }), 412, "ipam.revision_mismatch");
  });

  it("is written by administrators and operators only, and read by every account", async () => {
    await signInWithRoles(["viewer"]);
    expect((await view()).ssids).toHaveLength(3);
    expectProblem(await policy(HOME, "ignore"), 403, "auth.forbidden");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/policy`), 403, "auth.forbidden");
    expectProblem(await keep(HOME, "tv-living"), 403, "auth.forbidden");
    expectProblem(await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/exceptions/${HOST_IDS["tv-living"]}`), 403, "auth.forbidden");
    expect(mockTopologyDecisions.policies.size + mockTopologyDecisions.exceptions.size).toBe(0);
    await signInWithRoles(["operator"]);
    expect((await policy(HOME, "ignore")).status).toBe(200);
    expect((await keep(HOME, "tv-living")).status).toBe(200);
  });

  it("writes an audit record for each decision", async () => {
    await policy(HOME, "ignore");
    await keep(HOME, "tv-living", { reason: "kept" });
    await send("DELETE", `${V}/topology/ssids/${ssidPath(HOME)}/policy`);
    const records = (await get<{ items: S["AuditRecord"][] }>(`${V}/audit?limit=1000`)).body.items;
    expect(records.map((r) => r.draft.action)).toEqual(
      expect.arrayContaining(["ipam.wlan_policy.set", "ipam.wlan_exception.keep", "ipam.wlan_policy.clear"]),
    );
  });
});
