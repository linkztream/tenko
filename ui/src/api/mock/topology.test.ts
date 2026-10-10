// The topology map of the mock API through `fetch` against the msw server: the seeded graph
// and its consistency with the IPAM seed, the filters with the context rule of the server,
// the limit, and the view of one node with its ports, neighbours and intent.
import { beforeEach, describe, expect, it } from "vitest";
import { apiOperations } from "../generated/operations";
import type { components } from "../generated/schema";
import { db, resetMockDb } from "./db";
import { HOST_IDS, IPAM_IDS, applyCommands, ipamState } from "./ipam/api";
import { TOPOLOGY_COUNTS, TOPOLOGY_IDS, TOPOLOGY_SOURCES, TOPOLOGY_SSIDS, mockVlanController } from "./topology-store";

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
    expect(operations.map((o) => o.path).sort()).toEqual(["/api/v1/topology", "/api/v1/topology/nodes/{id}"]);
    for (const operation of operations) {
      const path = operation.path.replace("{id}", T.swCore);
      resetMockDb("signed-in");
      expect((await get(path)).status, path).toBe(200);
      resetMockDb("signed-out");
      expectProblem(await get(path), 401, "auth.unauthenticated");
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
      nodes: 24,
      edges: 23,
      total_nodes: 24,
      total_edges: 23,
      truncated: false,
      by_kind: { access_point: 3, container: 1, host: 14, hypervisor: 1, router: 1, switch: 2, vm: 2 },
      by_edge_kind: { lldp: 1, uplink: 4, vm_host: 3, wired: 9, wireless: 6 },
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
    for (const node of g.nodes.filter((n) => n.id !== T.apGarage && n.id !== T.unknown)) {
      expect(node.site, node.label).toBe(IPAM_IDS.site.home);
    }
    expect(byId.get(T.unknown)?.site).toBeUndefined();
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
    ]);
    for (const entry of g.summary.vlans) expect(entry.nodes).toBe(g.nodes.filter((n) => n.vlans?.includes(entry.vid)).length);
    expect(g.summary.controllers).toEqual([
      { connector: T.controller, name: "unifi.example.test", observed_at: g.summary.computed_at, devices: TOPOLOGY_COUNTS.controllerDevices },
    ]);
    expect(g.summary.networks).toEqual([
      { id: "net-mgmt", name: "Management", vlan: 10, subnet: "192.0.2.0/24", management: true, connector: T.controller },
      { id: "net-iot", name: "IoT", vlan: 30, subnet: "198.51.100.0/24", management: false, connector: T.controller },
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
    expect(garage.summary).toMatchObject({ nodes: 6, edges: 5, total_nodes: 24, total_edges: 23, truncated: false });
    expect(garage.summary.sites).toEqual([IPAM_IDS.site.home, IPAM_IDS.site.garage]);
    // Exactly the hosts of a site, without context: the unknown client has no site.
    const home = await graph(`?site=${IPAM_IDS.site.home}&kind=host`);
    expect(home.nodes).toHaveLength(13);
    expect(home.nodes.every((n) => n.kind === "host" && n.site === IPAM_IDS.site.home)).toBe(true);
    expect(ids(home)).not.toContain(T.unknown);
    expect(home.edges).toEqual([]);
    expect((await graph(`?site=${IPAM_IDS.site.lab}`)).nodes).toEqual([]);
    expect((await graph(`?site=${IPAM_IDS.site.lab}`)).summary).toMatchObject({ nodes: 0, edges: 0, total_nodes: 24, vlans: [], sites: [] });
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
    expect((await graph("?kind=")).nodes).toHaveLength(24);
    expect((await graph("?kind=,")).nodes).toHaveLength(24);
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
    expect(ids(await only("example devices", "host"))).toEqual([T.unknown]);
    expect(ids(await only("u6-lite", "access_point"))).toEqual(sorted([T.apGarage, T.apAttic]));
    expect(ids(await only("home.example", "access_point"))).toEqual(sorted([T.apHall, T.apAttic]));
    expect(ids(await only("iot.example", "access_point"))).toEqual(sorted([T.apHall, T.apGarage]));
    expect(ids(await only("iot.example", "host"))).toEqual(sorted(IOT));
    expect((await only("no such thing", "host")).nodes).toEqual([]);
    // Blank text keeps everything.
    expect((await graph("?q=")).nodes).toHaveLength(24);
    expect((await graph("?q=%20%20")).nodes).toHaveLength(24);
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
    expect(one.summary).toMatchObject({ nodes: 1, edges: 0, total_nodes: 24 });
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
    expect(lab.summary.total_nodes).toBe(24);
  });
});

describe("the limit", () => {
  it("cuts the answer and keeps the network devices first", async () => {
    const infrastructure = sorted(NETWORK_DEVICES);
    const three = await graph("?limit=3");
    expect(ids(three)).toEqual(infrastructure.slice(0, 3));
    expect(three.summary).toMatchObject({ nodes: 3, total_nodes: 24, truncated: true });
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
    expect((await graph("?limit=24")).summary).toMatchObject({ nodes: 24, truncated: false });
    expect((await graph("?limit=23")).summary).toMatchObject({ nodes: 23, truncated: true });
    expect((await graph()).summary.truncated).toBe(false);
    expect((await graph("?limit=20000")).nodes).toHaveLength(24);
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
      { node: T.gateway, label: "gw", kind: "router", edge: expect.stringMatching(/^e-/) as string, edge_kind: "uplink", port: "1", remote_port: "1" },
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
    expect(removed.nodes).toHaveLength(24);
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
