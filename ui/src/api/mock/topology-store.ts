// The topology of the mock lab (docs/topology.md, WP2.7): a static graph that matches the IPAM
// seed (ipam/seed.ts) and the observation seed (reconcile-store.ts), and the one network
// controller behind it. The server computes the graph from facts; the mock builds the same
// picture once per reset, from the hosts, MAC addresses, addresses, networks and VLANs of the
// IPAM mock, and keeps it fixed afterwards. The node view reads the intent live.
//
// The lab: the controller `unifi.example.test` reports a gateway (gw), two switches (sw-core,
// sw-desk) and three access points (ap-hall, ap-garage, ap-attic). gw, the switches and the
// first two access points are hosts of intent, so their nodes are `h-<host>`; ap-attic is
// known to the controller only (`c-...`). pve1 is a hypervisor with two virtual machines and a
// container (inventory nodes `i-...`). The IoT devices sit on the access points over the SSID
// `iot.example.test` (VLAN 30), one client is unknown (`m-<mac>`). The guest network
// `guest.example.test` (VLAN 40) carries one client, also without intent, on ap-attic.
import type { components } from "../generated/schema";
import { compareIp, containsIp, parseIp } from "../../ipam/ip";
import { db, onMockReset } from "./db";
import { HOST_IDS, IPAM_IDS, ipamState } from "./ipam/api";
import { cidrOf, ipOf } from "./ipam/net";
import { RECONCILE_IDS } from "./reconcile-store";
import { MINUTE, iso } from "./util";

type S = components["schemas"];
export type TopologyNode = S["TopologyNode"];
export type TopologyEdge = S["TopologyEdge"];
export type NodeKind = S["NodeKind"];
export type EdgeKind = S["EdgeKind"];
export type ControllerNetwork = S["ControllerNetwork"];
export type ControllerInfo = S["ControllerInfo"];
type RadioBand = S["RadioBand"];

// ---------------------------------------------------------------------------------
// The controller

/** The name of the network controller. */
export const CONTROLLER_NAME = "unifi.example.test";

/** The wireless networks of the lab and the VLAN each one carries. */
export const TOPOLOGY_SSIDS = { iot: "iot.example.test", home: "home.example.test", guest: "guest.example.test" } as const;
const SSID_VLAN: Readonly<Record<string, number>> = {
  [TOPOLOGY_SSIDS.iot]: 30,
  [TOPOLOGY_SSIDS.home]: 10,
  [TOPOLOGY_SSIDS.guest]: 40,
};
/** The wireless networks the controller reports, with the guest flag. */
const WLANS: readonly MockWlan[] = [
  { ssid: TOPOLOGY_SSIDS.home, vid: 10, guest: false, enabled: true },
  { ssid: TOPOLOGY_SSIDS.iot, vid: 30, guest: false, enabled: true },
  { ssid: TOPOLOGY_SSIDS.guest, vid: 40, guest: true, enabled: true },
];

/**
 * The mock network controller, shared by the topology and the VLAN provision. Tests change its
 * members in place (one object for the life of the module; a reset restores the seed):
 * `writes_enabled = false` makes it read-only (TGL-20), `enabled = false` disables it,
 * `present = false` removes it (no network controller is configured).
 */
export interface MockVlanController {
  /** False when no network controller is configured at all. */
  present: boolean;
  /** The connector instance. */
  id: string;
  name: string;
  plugin: string;
  enabled: boolean;
  /** Whether writes through the connector are allowed. */
  writes_enabled: boolean;
  /** Whether it can bounce a switch port (`port_bounce`) and disconnect a wireless client (`client_kick`), ADR 0028. */
  bounce: boolean;
  kick: boolean;
  /** The networks it has. Management on VLAN 10 is marked management and never written. */
  networks: ControllerNetwork[];
}

function freshController(): MockVlanController {
  return {
    present: true,
    id: RECONCILE_IDS.controller,
    name: CONTROLLER_NAME,
    plugin: "unifi",
    enabled: true,
    writes_enabled: true,
    bounce: true,
    kick: true,
    networks: [
      { id: "net-mgmt", name: "Management", vlan: 10, subnet: "192.0.2.0/24", management: true, dhcp: "server" },
      { id: "net-iot", name: "IoT", vlan: 30, subnet: "198.51.100.0/24", management: false, dhcp: "relay" },
    ],
  };
}

export const mockVlanController: MockVlanController = freshController();

onMockReset(() => {
  Object.assign(mockVlanController, freshController());
});

/** What the controller list reports about the mock controller. */
export function controllerInfo(): ControllerInfo {
  return {
    id: mockVlanController.id,
    name: mockVlanController.name,
    plugin: mockVlanController.plugin,
    enabled: mockVlanController.enabled,
    writes_enabled: mockVlanController.writes_enabled,
    bounce: mockVlanController.bounce,
    kick: mockVlanController.kick,
  };
}

// ---------------------------------------------------------------------------------
// Identifiers

const hostNode = (name: string): string => `h-${(HOST_IDS[name] ?? "").replace(/-/g, "")}`;

/**
 * The fixed identifiers of the seeded graph, so tests can refer to them. `h-` nodes are the
 * hosts of intent (the identifier follows the host of the IPAM seed), `c-` the controller
 * device that intent does not know, `i-` the inventory hosts, `m-` the client without intent.
 */
export const TOPOLOGY_IDS = {
  /** The connector instance of the network controller. */
  controller: RECONCILE_IDS.controller,
  gateway: hostNode("gw"),
  swCore: hostNode("sw-core"),
  swDesk: hostNode("sw-desk"),
  apHall: hostNode("ap-hall"),
  apGarage: hostNode("ap-garage"),
  /** An access point only the controller knows: no host of intent. */
  apAttic: "c-5ca1ab1e0a01",
  pve1: hostNode("pve1"),
  /** Virtual machines and a container on pve1 (inventory ids). */
  mediaPc: "i-3f6d1a9c0b01",
  buildVm: "i-3f6d1a9c0b02",
  dnsCt: "i-3f6d1a9c0b03",
  /** Wired hosts. */
  nas: hostNode("nas"),
  ha: hostNode("ha"),
  tenko1: hostNode("tenko1"),
  tenko2: hostNode("tenko2"),
  tenko3: hostNode("tenko3"),
  laptop: hostNode("laptop-ak"),
  printer: hostNode("printer-1"),
  /** IoT devices over `iot.example.test` (VLAN 30). */
  thermostat: hostNode("thermostat-1"),
  plug: hostNode("plug-kitchen"),
  camera: hostNode("cam-door"),
  speaker: hostNode("speaker-den"),
  sensor: hostNode("sensor-garage"),
  /** A wireless client over `home.example.test` (VLAN 10). */
  tv: hostNode("tv-living"),
  /** A client without intent (a vendor, no host). */
  unknown: "m-00005e0053d2",
  /** The one client of the guest network, also without intent. */
  guestClient: "m-00005e0053d3",
} as const;

/** The nodes and the number of edges of the seeded graph. */
export const TOPOLOGY_COUNTS = { nodes: 25, edges: 24, controllerDevices: 6 } as const;

// ---------------------------------------------------------------------------------
// The state

/** One line of a controller's port table. */
export interface MockPort {
  /** The index, written as text in the graph. */
  index: number;
  name: string;
  native_vlan: number | null;
  uplink: boolean;
  up: boolean;
}

/** A wireless network of the controller. */
export interface MockWlan {
  ssid: string;
  /** The VLAN it carries. */
  vid: number | null;
  guest: boolean;
  enabled: boolean;
}

/** A wireless client as the controller reports it: the table the SSID view reads. */
export interface MockWirelessClient {
  /** The client node. */
  node: string;
  mac: string;
  /** The address the controller reports. */
  ip?: string;
  ssid: string;
  vid: number;
  /** The node of the access point. */
  accessPoint: string;
  band: RadioBand;
}

export interface TopologyState {
  /** Nodes by identifier. */
  nodes: TopologyNode[];
  /** Edges by identifier. */
  edges: TopologyEdge[];
  /** The port table of a controller device, by node identifier. */
  ports: Map<string, MockPort[]>;
  /** How many devices the controller reports. */
  controllerDevices: number;
  /** When the graph was computed. */
  computedAt: string;
  /** The wireless networks the controller reports. */
  wlans: MockWlan[];
  /** The wireless clients the controller reports. */
  wireless: MockWirelessClient[];
  /**
   * The next hops of the default routes of the host Tenko runs on, the source of the second
   * root candidate. Default: the gateway's own address, so the sources agree; a test sets
   * another hop to make them disagree.
   */
  nextHops: string[];
}

let state: TopologyState | null = null;

/** The graph of the scenario: empty before the first-run setup, else built from the IPAM seed. */
function seed(): TopologyState {
  const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  return empty
    ? { nodes: [], edges: [], ports: new Map(), controllerDevices: 0, computedAt: iso(Date.now()), wlans: [], wireless: [], nextHops: [] }
    : buildTopology(Date.now());
}

// Built when the db resets (the IPAM state was reseeded by then), so a change of the IPAM mock
// after the reset does not change which nodes exist.
onMockReset(() => {
  state = seed();
});

/** The graph; built from the IPAM seed on first use when no reset came before. */
export function topologyState(): TopologyState {
  state ??= seed();
  return state;
}

// ---------------------------------------------------------------------------------
// Intent

interface Intent {
  host: string;
  macs: string[];
  ips: string[];
  prefixes: string[];
  site: string | null;
}

/** The most specific live prefix of a VRF that holds the address. */
function prefixOf(ip: string, vrf: string): string | null {
  const parsed = parseIp(ip);
  if (!parsed) return null;
  let best: { id: string; length: number } | null = null;
  for (const prefix of ipamState().data.prefix.values()) {
    if (prefix.meta.deleted || prefix.vrf !== vrf) continue;
    const cidr = cidrOf(prefix.cidr);
    if (containsIp(cidr, parsed) && (!best || best.length < cidr.length)) best = { id: prefix.id, length: cidr.length };
  }
  return best?.id ?? null;
}

/** The site of a node: the host's, else its network's, else its VLAN's. */
function siteOf(hostSite: string | null, prefixes: readonly string[]): string | null {
  if (hostSite) return hostSite;
  const data = ipamState().data;
  for (const id of prefixes) {
    const prefix = data.prefix.get(id);
    if (prefix?.site) return prefix.site;
  }
  for (const id of prefixes) {
    const vlan = data.vlan.get(data.prefix.get(id)?.vlan ?? "");
    if (vlan?.site) return vlan.site;
  }
  return null;
}

/** The VLAN ids of the networks that hold the addresses. */
function networkVlans(prefixes: readonly string[]): number[] {
  const data = ipamState().data;
  const out: number[] = [];
  for (const id of prefixes) {
    const vlan = data.vlan.get(data.prefix.get(id)?.vlan ?? "");
    if (vlan && !vlan.meta.deleted) out.push(vlan.vid);
  }
  return out;
}

/** A host of intent with its MAC addresses, addresses and the most specific networks. */
function intentOf(name: string): Intent | null {
  const data = ipamState().data;
  const id = HOST_IDS[name];
  const host = id ? data.host.get(id) : undefined;
  if (!host || host.meta.deleted) return null;
  const interfaces = [...data.interface.values()].filter((i) => i.host === host.id && !i.meta.deleted);
  const owned = new Set(interfaces.map((i) => i.id));
  const addresses = [...data.address.values()]
    .filter((a) => !a.meta.deleted && !!a.interface && owned.has(a.interface))
    .sort((a, b) => compareIp(ipOf(a.ip), ipOf(b.ip)));
  const prefixes = [...new Set(addresses.map((a) => a.prefix))];
  return {
    host: host.id,
    macs: interfaces.flatMap((i) => (i.mac ? [i.mac] : [])).sort(),
    ips: addresses.map((a) => a.ip),
    prefixes,
    site: siteOf(host.site ?? null, prefixes),
  };
}

// ---------------------------------------------------------------------------------
// Building the graph

const CONTROLLER_SOURCE = `network_controller:${RECONCILE_IDS.controller}`;
const SNMP_SOURCE = `probe:${RECONCILE_IDS.probeNode}:snmp`;
const INVENTORY_SOURCE = `inventory:${RECONCILE_IDS.inventory}`;

/** A stable 12-digit hexadecimal digest of the parts (not cryptographic). */
function hash12(parts: readonly string[]): string {
  const text = `${parts.join("\u001f")}\u001f`;
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x85ebca6b) >>> 0;
    h2 = (h2 ^ (h2 >>> 13)) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).slice(0, 12);
}

/** The label of a client without intent: the vendor with the end of the MAC address. */
function vendorLabel(vendor: string, mac: string): string {
  return `${vendor} ${mac.split(":").slice(-3).join(":")}`;
}

interface Def {
  id: string;
  kind: NodeKind;
  /** The host of intent (its name); the label, addresses and networks come from intent. */
  host?: string;
  /** Without a host: label, addresses. */
  label?: string;
  macs?: string[];
  ips?: string[];
  vendor?: string;
  model?: string;
  os?: string;
  ssids?: string[];
  sources: string[];
  /** Minutes since the last sighting. */
  seen: number;
}

interface LinkDef {
  kind: EdgeKind;
  a: string;
  aPort?: string;
  b: string;
  bPort?: string;
  vlan?: number;
  ssid?: string;
  /** Wireless: the band, and the address the controller reports. */
  band?: RadioBand;
  ip?: string;
  sources: string[];
}

const port = (index: number, options: { native?: number; uplink?: boolean; up?: boolean } = {}): MockPort => ({
  index,
  name: `Port ${index}`,
  native_vlan: options.native ?? null,
  uplink: options.uplink ?? false,
  up: options.up ?? true,
});

function definitions(): Def[] {
  const intentSources = ["intent", CONTROLLER_SOURCE];
  const device = (id: string, kind: NodeKind, host: string, model: string, ssids?: string[]): Def => ({
    id,
    kind,
    host,
    model,
    ...(ssids ? { ssids } : {}),
    sources: intentSources,
    seen: 1,
  });
  const client = (id: string, host: string, seen: number, ssid?: string, extra: Partial<Def> = {}): Def => ({
    id,
    kind: "host",
    host,
    ...(ssid ? { ssids: [ssid] } : {}),
    sources: intentSources,
    seen,
    ...extra,
  });
  const T = TOPOLOGY_IDS;
  return [
    device(T.gateway, "router", "gw", "UDM-Pro"),
    device(T.swCore, "switch", "sw-core", "USW-24-PoE"),
    device(T.swDesk, "switch", "sw-desk", "USW-Lite-8-PoE"),
    device(T.apHall, "access_point", "ap-hall", "U6-Pro", [TOPOLOGY_SSIDS.home, TOPOLOGY_SSIDS.iot]),
    device(T.apGarage, "access_point", "ap-garage", "U6-Lite", [TOPOLOGY_SSIDS.iot]),
    {
      id: T.apAttic,
      kind: "access_point",
      label: "ap-attic",
      macs: ["00:00:5e:00:53:a6"],
      ips: ["192.0.2.6"],
      model: "U6-Lite",
      ssids: [TOPOLOGY_SSIDS.home, TOPOLOGY_SSIDS.guest],
      sources: [CONTROLLER_SOURCE],
      seen: 2,
    },
    { ...client(T.pve1, "pve1", 2, undefined, { kind: "hypervisor", os: "Proxmox VE 8.2" }), sources: ["intent", INVENTORY_SOURCE, CONTROLLER_SOURCE] },
    {
      id: T.mediaPc,
      kind: "vm",
      label: "media-pc",
      macs: ["00:00:5e:00:53:d1"],
      ips: ["192.0.2.150"],
      os: "Debian 12",
      sources: [INVENTORY_SOURCE],
      seen: 10,
    },
    {
      id: T.buildVm,
      kind: "vm",
      label: "build-vm",
      macs: ["00:00:5e:00:53:d6"],
      ips: ["192.0.2.151"],
      os: "Ubuntu 24.04",
      sources: [INVENTORY_SOURCE],
      seen: 10,
    },
    {
      id: T.dnsCt,
      kind: "container",
      label: "dns-ct",
      macs: ["00:00:5e:00:53:d7"],
      ips: ["192.0.2.152"],
      os: "Alpine 3.20",
      sources: [INVENTORY_SOURCE],
      seen: 10,
    },
    { ...client(T.nas, "nas", 3), sources: ["intent", CONTROLLER_SOURCE, SNMP_SOURCE] },
    client(T.ha, "ha", 3),
    client(T.tenko1, "tenko1", 4),
    client(T.tenko2, "tenko2", 4),
    client(T.tenko3, "tenko3", 4),
    client(T.laptop, "laptop-ak", 6),
    // Seen in the bridge table of a probe only, so its edge is inferred.
    { ...client(T.printer, "printer-1", 9), sources: ["intent", SNMP_SOURCE] },
    client(T.thermostat, "thermostat-1", 5, TOPOLOGY_SSIDS.iot),
    client(T.plug, "plug-kitchen", 5, TOPOLOGY_SSIDS.iot),
    client(T.camera, "cam-door", 5, TOPOLOGY_SSIDS.iot),
    client(T.speaker, "speaker-den", 7, TOPOLOGY_SSIDS.iot),
    client(T.sensor, "sensor-garage", 5, TOPOLOGY_SSIDS.iot),
    client(T.tv, "tv-living", 8, TOPOLOGY_SSIDS.home),
    {
      id: T.guestClient,
      kind: "host",
      label: vendorLabel("Example Devices", "00:00:5e:00:53:d3"),
      macs: ["00:00:5e:00:53:d3"],
      vendor: "Example Devices",
      ssids: [TOPOLOGY_SSIDS.guest],
      sources: [CONTROLLER_SOURCE],
      seen: 3,
    },
    {
      id: T.unknown,
      kind: "host",
      label: vendorLabel("Example Devices", "00:00:5e:00:53:d2"),
      macs: ["00:00:5e:00:53:d2"],
      vendor: "Example Devices",
      sources: [CONTROLLER_SOURCE],
      seen: 12,
    },
  ];
}

function links(): LinkDef[] {
  const T = TOPOLOGY_IDS;
  const c = [CONTROLLER_SOURCE];
  const wired = (sw: string, p: string, client: string, vlan: number, sources = c): LinkDef => ({
    kind: "wired",
    a: sw,
    aPort: p,
    b: client,
    vlan,
    sources,
  });
  // The IoT clients report an address of the IoT network (198.51.100.0/24, VLAN 30), as the
  // controller sees their leases there.
  const wireless = (ap: string, client: string, ssid: string, band: RadioBand, ip?: string): LinkDef => ({
    kind: "wireless",
    a: ap,
    b: client,
    ssid,
    vlan: SSID_VLAN[ssid] ?? 10,
    band,
    ...(ip ? { ip } : {}),
    sources: c,
  });
  const iot = TOPOLOGY_SSIDS.iot;
  return [
    { kind: "uplink", a: T.gateway, aPort: "1", b: T.swCore, bPort: "1", sources: c },
    { kind: "lldp", a: T.swCore, aPort: "6", b: T.swDesk, bPort: "1", sources: [CONTROLLER_SOURCE, SNMP_SOURCE] },
    { kind: "uplink", a: T.apHall, b: T.swCore, bPort: "7", sources: c },
    { kind: "uplink", a: T.apGarage, b: T.swDesk, bPort: "6", sources: c },
    { kind: "uplink", a: T.apAttic, b: T.swDesk, bPort: "8", sources: c },
    wired(T.swCore, "2", T.pve1, 10),
    wired(T.swCore, "3", T.nas, 10, [CONTROLLER_SOURCE, SNMP_SOURCE]),
    wired(T.swCore, "4", T.ha, 10),
    wired(T.swCore, "5", T.printer, 10, [SNMP_SOURCE]),
    wired(T.swDesk, "2", T.tenko1, 20),
    wired(T.swDesk, "3", T.tenko2, 20),
    wired(T.swDesk, "4", T.tenko3, 20),
    wired(T.swDesk, "5", T.laptop, 10),
    wired(T.swDesk, "7", T.unknown, 10),
    wireless(T.apHall, T.plug, iot, "2g", "198.51.100.42"),
    wireless(T.apHall, T.camera, iot, "5g", "198.51.100.43"),
    wireless(T.apHall, T.speaker, iot, "5g", "198.51.100.45"),
    wireless(T.apHall, T.tv, TOPOLOGY_SSIDS.home, "6g", "192.0.2.57"),
    wireless(T.apGarage, T.thermostat, iot, "2g", "198.51.100.41"),
    wireless(T.apGarage, T.sensor, iot, "2g", "198.51.100.44"),
    wireless(T.apAttic, T.guestClient, TOPOLOGY_SSIDS.guest, "5g", "203.0.113.130"),
    { kind: "vm_host", a: T.pve1, b: T.mediaPc, sources: [INVENTORY_SOURCE] },
    { kind: "vm_host", a: T.pve1, b: T.buildVm, sources: [INVENTORY_SOURCE] },
    { kind: "vm_host", a: T.pve1, b: T.dnsCt, sources: [INVENTORY_SOURCE] },
  ];
}

/** The port tables of the controller devices. */
function portTables(): Map<string, MockPort[]> {
  const T = TOPOLOGY_IDS;
  return new Map<string, MockPort[]>([
    [T.gateway, [port(1, { native: 10 }), port(2, { uplink: true })]],
    [
      T.swCore,
      [
        port(1, { native: 10, uplink: true }),
        port(2, { native: 10 }),
        port(3, { native: 10 }),
        port(4, { native: 10 }),
        port(5, { native: 10 }),
        port(6, { native: 10 }),
        port(7, { native: 10 }),
        port(8, { native: 10, up: false }),
      ],
    ],
    [
      T.swDesk,
      [
        port(1, { native: 10, uplink: true }),
        port(2, { native: 20 }),
        port(3, { native: 20 }),
        port(4, { native: 20 }),
        port(5, { native: 10 }),
        port(6, { native: 10 }),
        port(7, { native: 10 }),
        port(8, { native: 10 }),
      ],
    ],
  ]);
}

function buildTopology(now: number): TopologyState {
  const data = ipamState().data;
  const defaultVrf = [...data.vrf.values()].find((v) => v.name === "default")?.id ?? IPAM_IDS.vrf.default;
  const ports = portTables();

  const edges: TopologyEdge[] = links().map((link) => {
    let { a, aPort, b, bPort } = link;
    // A link between two devices has no direction: the smaller identifier comes first.
    if ((link.kind === "lldp" || link.kind === "uplink") && b < a) [a, aPort, b, bPort] = [b, bPort, a, aPort];
    const edge: TopologyEdge = {
      id: `e-${hash12([link.kind, a, aPort ?? "", b, bPort ?? ""])}`,
      kind: link.kind,
      a,
      b,
      sources: [...link.sources].sort(),
    };
    // A client edge no network controller reports is only inferred (a bridge table of a probe).
    edge.inferred =
      (link.kind === "wired" || link.kind === "wireless") && !link.sources.some((s) => s.startsWith("network_controller:"));
    if (aPort !== undefined) edge.a_port = aPort;
    if (bPort !== undefined) edge.b_port = bPort;
    if (link.vlan !== undefined) edge.vlan = link.vlan;
    if (link.ssid !== undefined) edge.ssid = link.ssid;
    return edge;
  });

  // The VLANs a client is attached in, by node.
  const attached = new Map<string, number[]>();
  for (const edge of edges) {
    if ((edge.kind === "wired" || edge.kind === "wireless") && edge.vlan != null) {
      attached.set(edge.b, [...(attached.get(edge.b) ?? []), edge.vlan]);
    }
  }

  const nodes: TopologyNode[] = [];
  for (const def of definitions()) {
    const intent = def.host ? intentOf(def.host) : null;
    if (def.host && !intent) continue;
    const ips = intent ? intent.ips : (def.ips ?? []);
    const macs = intent ? intent.macs : (def.macs ?? []);
    const prefixes = intent
      ? intent.prefixes
      : [...new Set(ips.flatMap((ip) => prefixOf(ip, defaultVrf) ?? []))];
    const vlans = new Set<number>(networkVlans(prefixes));
    for (const vid of attached.get(def.id) ?? []) vlans.add(vid);
    for (const entry of ports.get(def.id) ?? []) if (entry.native_vlan !== null) vlans.add(entry.native_vlan);
    if (def.kind === "access_point") for (const ssid of def.ssids ?? []) vlans.add(SSID_VLAN[ssid] ?? 10);
    const site = intent ? intent.site : siteOf(null, prefixes);
    const first = macs[0] ?? ips[0];
    const node: TopologyNode = {
      id: def.id,
      kind: def.kind,
      label: intent ? def.host ?? def.id : (def.label ?? def.id),
      sources: [...def.sources].sort(),
    };
    if (macs.length > 0) node.macs = macs;
    if (ips.length > 0) node.ips = ips;
    if (def.vendor) node.vendor = def.vendor;
    if (def.model) node.model = def.model;
    if (def.os) node.os = def.os;
    if (intent) node.host = intent.host;
    if (first !== undefined) node.subject = first;
    if (vlans.size > 0) node.vlans = [...vlans].sort((x, y) => x - y);
    if (prefixes.length > 0) node.prefixes = prefixes;
    if (site) node.site = site;
    if (def.ssids && def.ssids.length > 0) node.ssids = [...def.ssids].sort();
    node.last_seen = iso(now - def.seen * MINUTE);
    nodes.push(node);
  }
  nodes.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  const kept = new Set(nodes.map((n) => n.id));
  const wholeEdges = edges.filter((e) => kept.has(e.a) && kept.has(e.b));
  wholeEdges.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  const tables = new Map([...ports].filter(([id]) => kept.has(id)));
  const byId = new Map(nodes.map((n) => [n.id, n] as const));
  const wireless: MockWirelessClient[] = [];
  for (const link of links()) {
    const client = byId.get(link.b);
    const mac = client?.macs?.[0];
    if (link.kind !== "wireless" || !client || mac === undefined || !byId.has(link.a)) continue;
    wireless.push({
      node: client.id,
      mac,
      ...(link.ip ? { ip: link.ip } : {}),
      ssid: link.ssid ?? "",
      vid: link.vlan ?? 0,
      accessPoint: link.a,
      band: link.band ?? "5g",
    });
  }
  const gateway = byId.get(TOPOLOGY_IDS.gateway);
  return {
    nodes,
    edges: wholeEdges,
    ports: tables,
    controllerDevices: nodes.filter((n) => n.sources.includes(CONTROLLER_SOURCE) && isController(n)).length,
    computedAt: iso(now),
    wlans: WLANS.map((wlan) => ({ ...wlan })),
    wireless,
    nextHops: gateway?.ips?.[0] ? [gateway.ips[0]] : [],
  };
}

/** Whether the controller reports the node as one of its devices. */
function isController(node: TopologyNode): boolean {
  return node.kind === "router" || node.kind === "switch" || node.kind === "access_point";
}

/** The sources of the controller, for tests that look for the edges it reports. */
export const TOPOLOGY_SOURCES = {
  controller: CONTROLLER_SOURCE,
  snmp: SNMP_SOURCE,
  inventory: INVENTORY_SOURCE,
} as const;
