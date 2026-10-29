// The topology map of the mock API (docs/topology.md, WP2.7): `GET /topology` answers the nodes,
// the edges and a summary with the filters of the server (crates/tenko-ipam/src/topology/
// filter.rs), `GET /topology/nodes/{id}` one node with its ports, neighbours and intent.
//
// The graph is static (topology-store.ts); the filters, the context rule, the truncation, the
// summary and the node view follow the server. The VLAN and network names and the intent come
// live from the IPAM mock. Every signed-in account may read.
//
// The root of the map, the SSID view and the decisions on them (`/topology/root`,
// `/topology/ssids` and below) are served from topology-decisions.ts; administrators and
// operators write them, as they write the other IPAM objects.
import type { HttpHandler } from "msw";
import { compareIp, containsIp, parseCidr, parseIp, type Cidr } from "../../ipam/ip";
import type { components } from "../generated/schema";
import { requireSession } from "./auth";
import { db, isAdmin } from "./db";
import { ipamState } from "./ipam/api";
import { ipOf } from "./ipam/net";
import { invalidQuery, notFound } from "./ipam/problems";
import { Query } from "./ipam/query";
import { Problem, fail, noContent, ok } from "./reply";
import { route } from "./route";
import {
  chooseRoot,
  clearPolicy,
  clearRoot,
  forgetException,
  keepOnWlan,
  rootDecision,
  setPolicy,
  ssidView,
} from "./topology-decisions";
import {
  mockVlanController,
  topologyState,
  type NodeKind,
  type TopologyEdge,
  type TopologyNode,
  type TopologyState,
} from "./topology-store";
import { isUuid } from "./util";

type S = components["schemas"];
type Neighbour = S["Neighbour"];
type TopologyPort = S["TopologyPort"];
type TopologyGraph = S["TopologyGraph"];
type TopologyNodeView = S["TopologyNodeView"];
type NodeIntent = S["NodeIntent"];
type TopologySummary = S["TopologySummary"];

/** The default node limit of an answer and the largest a caller may ask for. */
export const DEFAULT_LIMIT = 5_000;
export const MAX_LIMIT = 20_000;

export const NODE_KINDS: readonly NodeKind[] = ["router", "switch", "access_point", "hypervisor", "vm", "container", "host", "device"];

/** Whether the kind forwards traffic for others (the backbone of the map). */
function infrastructure(kind: NodeKind): boolean {
  return kind === "router" || kind === "switch" || kind === "access_point" || kind === "device";
}

// ---------------------------------------------------------------------------------
// The filter

interface Filter {
  site: string | null;
  vlan: number | null;
  within: Cidr | null;
  kinds: NodeKind[];
  q: string | null;
  limit: number | null;
}

/** A single parameter; blank values count as absent, repeating it is `sys.invalid_query`. */
function single(query: Query, name: string): string | null {
  const value = query.one(name)?.trim() ?? "";
  return value === "" ? null : value;
}

function readFilter(url: URL): Filter {
  const query = new Query(url, ["site", "vlan", "prefix", "within", "kind", "q", "limit", "cursor", "at_least"]);
  const kinds = query.all("kind").map((name) => {
    const kind = name.toLowerCase() as NodeKind;
    if (!NODE_KINDS.includes(kind)) {
      throw invalidQuery("kind", name, `\`${name}\` is not a node kind; allowed: ${NODE_KINDS.join(", ")}`);
    }
    return kind;
  });
  const rawLimit = single(query, "limit");
  let limit: number | null = null;
  if (rawLimit !== null) {
    limit = /^\d+$/.test(rawLimit) ? Number(rawLimit) : Number.NaN;
    if (!Number.isInteger(limit)) throw invalidQuery("limit", rawLimit, "limit must be a whole number");
    if (limit < 1 || limit > MAX_LIMIT) throw invalidQuery("limit", rawLimit, `${limit} is outside 1 to ${MAX_LIMIT}`);
  }
  const data = ipamState().data;
  let vlan: number | null = null;
  const rawVlan = single(query, "vlan");
  if (rawVlan !== null) {
    if (/^\d+$/.test(rawVlan) && Number(rawVlan) <= 65_535) {
      vlan = Number(rawVlan);
      if (vlan < 1 || vlan > 4094) throw invalidQuery("vlan", rawVlan, `${vlan} is outside 1 to 4094`);
    } else {
      if (!isUuid(rawVlan)) throw invalidQuery("vlan", rawVlan, "not a VLAN id or a VLAN identifier");
      const found = data.vlan.get(rawVlan.toLowerCase());
      if (!found) throw notFound("vlan", rawVlan.toLowerCase());
      vlan = found.vid;
    }
  }
  const rawWithin = single(query, "within");
  let within: Cidr | null = null;
  if (rawWithin !== null) {
    // A bare address is a host network; host bits must be zero.
    within = parseCidr(rawWithin);
    if (!within) throw invalidQuery("within", rawWithin, "expected a network such as 192.0.2.0/24");
  }
  const rawPrefix = single(query, "prefix");
  if (rawPrefix !== null) {
    if (!isUuid(rawPrefix)) throw invalidQuery("prefix", rawPrefix, "not a prefix identifier");
    if (within) throw invalidQuery("prefix", rawPrefix, "give either `prefix` or `within`");
    const found = data.prefix.get(rawPrefix.toLowerCase());
    if (!found) throw notFound("prefix", rawPrefix.toLowerCase());
    within = parseCidr(found.cidr);
  }
  const rawSite = single(query, "site");
  if (rawSite !== null && !isUuid(rawSite)) throw invalidQuery("site", rawSite, "not a site identifier");
  return { site: rawSite?.toLowerCase() ?? null, vlan, within, kinds, q: single(query, "q"), limit };
}

function isEmpty(filter: Filter): boolean {
  return !filter.site && filter.vlan === null && !filter.within && filter.kinds.length === 0 && !filter.q;
}

function matches(node: TopologyNode, filter: Filter): boolean {
  if (filter.site && node.site !== filter.site) return false;
  if (filter.vlan !== null && !(node.vlans ?? []).includes(filter.vlan)) return false;
  const within = filter.within;
  if (within && !(node.ips ?? []).some((ip) => {
    const parsed = parseIp(ip);
    return parsed !== null && containsIp(within, parsed);
  })) {
    return false;
  }
  if (filter.kinds.length > 0 && !filter.kinds.includes(node.kind)) return false;
  if (filter.q) {
    const q = filter.q.toLowerCase();
    const hit =
      node.label.toLowerCase().includes(q) ||
      (node.macs ?? []).some((mac) => mac.toLowerCase().includes(q)) ||
      (node.ips ?? []).some((ip) => ip.toLowerCase().includes(q)) ||
      (node.vendor ?? "").toLowerCase().includes(q) ||
      (node.model ?? "").toLowerCase().includes(q) ||
      (node.ssids ?? []).some((ssid) => ssid.toLowerCase().includes(q));
    if (!hit) return false;
  }
  return true;
}

/** The neighbours of every node: (edge, other node). */
function adjacency(edges: readonly TopologyEdge[]): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const push = (from: string, to: string): void => {
    const list = map.get(from);
    if (list) list.push(to);
    else map.set(from, [to]);
  };
  for (const edge of edges) {
    push(edge.a, edge.b);
    push(edge.b, edge.a);
  }
  return map;
}

function plainCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Applies a filter to the whole graph. Without a kind filter the answer adds the context of
 * the kept nodes: the network devices and hypervisors next to them and every network device
 * reachable from those over links between network devices. Edges are kept when both ends are.
 */
function apply(graph: TopologyState, filter: Filter): TopologyGraph {
  const limit = Math.min(Math.max(filter.limit ?? DEFAULT_LIMIT, 1), MAX_LIMIT);
  const keep = new Set<string>();
  if (isEmpty(filter)) {
    for (const node of graph.nodes) keep.add(node.id);
  } else {
    const kindOf = new Map(graph.nodes.map((n) => [n.id, n.kind] as const));
    const isInfrastructure = (id: string): boolean => {
      const kind = kindOf.get(id);
      return kind !== undefined && infrastructure(kind);
    };
    // A hypervisor is the context of its virtual machines and containers.
    const isContext = (id: string): boolean => isInfrastructure(id) || kindOf.get(id) === "hypervisor";
    for (const node of graph.nodes) if (matches(node, filter)) keep.add(node.id);
    if (filter.kinds.length === 0) {
      const adjacent = adjacency(graph.edges);
      const queue: string[] = [];
      for (const id of [...keep]) {
        for (const other of adjacent.get(id) ?? []) {
          if (isContext(other) && !keep.has(other)) {
            keep.add(other);
            queue.push(other);
          }
        }
        if (isContext(id)) queue.push(id);
      }
      // The backbone: network devices reachable over links between network devices.
      for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
        for (const other of adjacent.get(next) ?? []) {
          if (isInfrastructure(other) && !keep.has(other)) {
            keep.add(other);
            queue.push(other);
          }
        }
      }
    }
  }
  let truncated = false;
  let kept = keep;
  if (keep.size > limit) {
    truncated = true;
    // Network devices first, so the backbone survives the cut.
    const ordered = graph.nodes
      .filter((n) => keep.has(n.id))
      .sort((a, b) => Number(!infrastructure(a.kind)) - Number(!infrastructure(b.kind)) || plainCompare(a.id, b.id));
    kept = new Set(ordered.slice(0, limit).map((n) => n.id));
  }
  const nodes = graph.nodes.filter((n) => kept.has(n.id)).map((n) => structuredClone(n));
  const edges = graph.edges.filter((e) => kept.has(e.a) && kept.has(e.b)).map((e) => structuredClone(e));
  return summarize({
    nodes,
    edges,
    revision: db.revision,
    summary: wholeSummary(graph, truncated),
  });
}

/** The summary members that describe the whole graph and the controllers. */
function wholeSummary(graph: TopologyState, truncated: boolean): TopologySummary {
  const controller = mockVlanController;
  const listed = controller.present && controller.enabled;
  const summary: TopologySummary = {
    nodes: 0,
    edges: 0,
    total_nodes: graph.nodes.length,
    total_edges: graph.edges.length,
    by_kind: {},
    by_edge_kind: {},
    vlans: [],
    sites: [],
    controllers: listed
      ? [
          {
            connector: controller.id,
            name: controller.name,
            observed_at: graph.computedAt,
            devices: graph.controllerDevices,
            writes_enabled: controller.writes_enabled,
          },
        ]
      : [],
    networks: listed
      ? [...controller.networks]
          .sort((a, b) => (a.vlan ?? 0) - (b.vlan ?? 0) || plainCompare(a.name, b.name))
          .map((network) => ({ ...network, connector: controller.id }))
      : [],
    computed_at: graph.computedAt,
  };
  summary.truncated = truncated;
  const root = graph.nodes.length > 0 ? rootDecision().root : null;
  if (root) summary.root = root;
  return summary;
}

/** Fills the counts of a graph's summary from its nodes and edges. */
function summarize(graph: TopologyGraph): TopologyGraph {
  const byKind = new Map<string, number>();
  const vlanCounts = new Map<number, number>();
  const sites = new Set<string>();
  for (const node of graph.nodes) {
    byKind.set(node.kind, (byKind.get(node.kind) ?? 0) + 1);
    for (const vid of node.vlans ?? []) vlanCounts.set(vid, (vlanCounts.get(vid) ?? 0) + 1);
    if (node.site) sites.add(node.site);
  }
  const byEdgeKind = new Map<string, number>();
  for (const edge of graph.edges) byEdgeKind.set(edge.kind, (byEdgeKind.get(edge.kind) ?? 0) + 1);
  const liveVlans = [...ipamState().data.vlan.values()].filter((v) => !v.meta.deleted);
  const sortedEntries = <T,>(map: Map<string, T>): Record<string, T> =>
    Object.fromEntries([...map].sort(([a], [b]) => plainCompare(a, b)));
  graph.summary.nodes = graph.nodes.length;
  graph.summary.edges = graph.edges.length;
  graph.summary.by_kind = sortedEntries(byKind);
  graph.summary.by_edge_kind = sortedEntries(byEdgeKind);
  graph.summary.sites = [...sites].sort(plainCompare);
  graph.summary.vlans = [...vlanCounts]
    .sort(([a], [b]) => a - b)
    .map(([vid, nodes]) => {
      // A global VLAN names the id when one exists, else the first by name.
      const candidates = liveVlans
        .filter((v) => v.vid === vid)
        .sort((a, b) => Number(a.site !== null) - Number(b.site !== null) || plainCompare(a.name, b.name));
      const vlan = candidates[0];
      return { vid, nodes, ...(vlan ? { vlan: vlan.id, name: vlan.name } : {}) };
    });
  return graph;
}

// ---------------------------------------------------------------------------------
// One node

/** Ports order numerically where they are numbers, else by text; a missing port last. */
function portOrder(port: string | null | undefined): [number, number, string] {
  if (port === null || port === undefined) return [2, 0, ""];
  if (/^\d+$/.test(port)) return [0, Number(port), ""];
  return [1, 0, port];
}

function comparePorts(a: string | null | undefined, b: string | null | undefined): number {
  const [ka, na, ta] = portOrder(a);
  const [kb, nb, tb] = portOrder(b);
  return ka - kb || na - nb || plainCompare(ta, tb);
}

/** The neighbours of a node across every edge, ordered by port and label. */
export function neighboursOf(graph: TopologyState, id: string): Neighbour[] {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n] as const));
  const out: Neighbour[] = [];
  for (const edge of graph.edges) {
    let other: string;
    let port: string | null | undefined;
    let remote: string | null | undefined;
    if (edge.a === id) [other, port, remote] = [edge.b, edge.a_port, edge.b_port];
    else if (edge.b === id) [other, port, remote] = [edge.a, edge.b_port, edge.a_port];
    else continue;
    const node = nodes.get(other);
    if (!node) continue;
    const neighbour: Neighbour = { node: node.id, label: node.label, kind: node.kind, edge: edge.id, edge_kind: edge.kind };
    if (port != null) neighbour.port = port;
    if (remote != null) neighbour.remote_port = remote;
    if (edge.vlan != null) neighbour.vlan = edge.vlan;
    if (edge.ssid != null) neighbour.ssid = edge.ssid;
    if (edge.inferred !== undefined) neighbour.inferred = edge.inferred;
    out.push(neighbour);
  }
  return out.sort((a, b) => comparePorts(a.port, b.port) || plainCompare(a.label, b.label) || plainCompare(a.node, b.node));
}

/**
 * The ports of a node: the controller's port table (with what hangs on each port) and every
 * port its edges name; with `only`, that port alone (matched by the port or its name).
 */
function portsOf(graph: TopologyState, id: string, only: string | null): TopologyPort[] {
  const ports = new Map<string, TopologyPort>();
  for (const entry of graph.ports.get(id) ?? []) {
    const key = String(entry.index);
    const port: TopologyPort = { port: key, name: entry.name, uplink: entry.uplink, up: entry.up, neighbours: [] };
    if (entry.native_vlan !== null) port.native_vlan = entry.native_vlan;
    ports.set(key, port);
  }
  for (const neighbour of neighboursOf(graph, id)) {
    if (neighbour.port == null) continue;
    let port = ports.get(neighbour.port);
    if (!port) {
      port = { port: neighbour.port, uplink: false, neighbours: [] };
      ports.set(neighbour.port, port);
    }
    port.neighbours.push(neighbour);
  }
  return [...ports.values()]
    .sort((a, b) => comparePorts(a.port, b.port))
    .filter((port) => only === null || port.port === only || port.name === only);
}

/** The host of intent behind a node with its live addresses. */
function intentOf(hostId: string): NodeIntent | null {
  const data = ipamState().data;
  const host = data.host.get(hostId);
  if (!host || host.meta.deleted) return null;
  const owned = new Set([...data.interface.values()].filter((i) => i.host === host.id && !i.meta.deleted).map((i) => i.id));
  const addresses = [...data.address.values()]
    .filter((a) => !a.meta.deleted && !!a.interface && owned.has(a.interface))
    .sort((a, b) => compareIp(ipOf(a.ip), ipOf(b.ip)))
    .flatMap((address) => {
      const prefix = data.prefix.get(address.prefix);
      if (!prefix) return [];
      const vlan = prefix.vlan ? data.vlan.get(prefix.vlan) : undefined;
      const entry: NodeIntent["addresses"][number] = { ip: address.ip, prefix: prefix.id, cidr: prefix.cidr };
      if (prefix.vlan) entry.vlan = prefix.vlan;
      if (vlan) entry.vid = vlan.vid;
      return [entry];
    });
  return { host: host.id, name: host.name, mode: host.mode, addresses };
}

// ---------------------------------------------------------------------------------
// Routes

const graphRoute = route("get", "/api/v1/topology", (ctx) => {
  requireSession();
  const filter = readFilter(ctx.url);
  return ok(apply(topologyState(), filter));
});

const nodeRoute = route("get", "/api/v1/topology/nodes/{id}", (ctx) => {
  requireSession();
  const query = new Query(ctx.url, ["port", "limit", "cursor", "at_least"]);
  const limit = single(query, "limit");
  if (limit !== null && !(/^\d+$/.test(limit) && Number(limit) >= 1 && Number(limit) <= 1000)) {
    throw invalidQuery("limit", limit, "limit must be a whole number from 1 to 1000");
  }
  const only = single(query, "port");
  const graph = topologyState();
  const id = ctx.params.id;
  const node = graph.nodes.find((n) => n.id === id);
  if (!node) {
    throw new Problem("ipam.topology.not_found", {
      status: 404,
      detail: `the topology has no node ${id}`,
      params: { id },
    });
  }
  const view: TopologyNodeView = {
    node: structuredClone(node),
    ports: portsOf(graph, id, only),
    neighbours: neighboursOf(graph, id),
    revision: db.revision,
  };
  const intent = node.host ? intentOf(node.host) : null;
  if (intent) view.intent = intent;
  return ok(view);
});

// ---------------------------------------------------------------------------------
// The root, the SSIDs and the decisions on them (routes/topology/decisions.rs)

/** Operators and administrators write the decisions, as the IPAM writes of the server need. */
function requireWriter(): void {
  const principal = requireSession();
  if (!isAdmin(principal.user) && !principal.user.roles.includes("operator")) {
    throw new Problem("auth.forbidden", { status: 403, detail: "this needs the permission to change IPAM objects" });
  }
}

const etagged = <T extends { revision?: number }>(row: T) => ({ ETag: `"${row.revision ?? 0}"` });

/** The members of a body, none other than `allowed` (the server refuses unknown members). */
function checkMembers(body: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      fail("sys.invalid_request", { detail: `the body is not a valid request: unknown field \`${key}\`, expected one of ${allowed.join(", ")}` });
    }
  }
}

function oneOf<T extends string>(body: Record<string, unknown>, name: string, values: readonly T[]): T {
  const value = body[name];
  if (typeof value !== "string" || !values.includes(value as T)) {
    return fail("sys.invalid_request", { detail: `the body is not a valid request: \`${name}\` must be one of ${values.join(", ")}` });
  }
  return value as T;
}

const rootGet = route("get", "/api/v1/topology/root", () => {
  requireSession();
  const decision = rootDecision();
  return ok(decision, decision.choice ? etagged(decision.choice) : undefined);
});

const rootPut = route("put", "/api/v1/topology/root", async (ctx) => {
  requireWriter();
  const body = await ctx.body();
  checkMembers(body, ["source"]);
  const source = oneOf(body, "source", ["controller", "default_route"] as const);
  return ok(chooseRoot(source, ctx.ifMatch()));
});

const rootDelete = route("delete", "/api/v1/topology/root", (ctx) => {
  requireWriter();
  clearRoot(ctx.ifMatch());
  return noContent();
});

const ssidsGet = route("get", "/api/v1/topology/ssids", () => {
  requireSession();
  return ok(ssidView());
});

const policyPut = route("put", "/api/v1/topology/ssids/{ssid}/policy", async (ctx) => {
  requireWriter();
  const body = await ctx.body();
  checkMembers(body, ["policy"]);
  const policy = oneOf(body, "policy", ["track", "ignore"] as const);
  const row = setPolicy(ctx.params.ssid, policy, ctx.ifMatch());
  return ok(row, etagged(row));
});

const policyDelete = route("delete", "/api/v1/topology/ssids/{ssid}/policy", (ctx) => {
  requireWriter();
  clearPolicy(ctx.params.ssid, ctx.ifMatch());
  return noContent();
});

/** The host of a path: a UUID, else 400 `sys.invalid_request`. */
function hostOfPath(id: string): string {
  if (!isUuid(id)) fail("sys.invalid_request", { detail: `the host identifier ${id} is malformed`, params: { part: "path" } });
  return id.toLowerCase();
}

const exceptionPut = route("put", "/api/v1/topology/ssids/{ssid}/exceptions/{host}", async (ctx) => {
  requireWriter();
  const host = hostOfPath(ctx.params.host);
  // An empty body keeps without a reason.
  const body = await ctx.optionalBody();
  checkMembers(body, ["reason"]);
  const reason = body.reason;
  if (reason !== undefined && reason !== null && typeof reason !== "string") {
    fail("sys.invalid_request", { detail: "the body is not a valid request: `reason` must be a text" });
  }
  const row = keepOnWlan(host, ctx.params.ssid, typeof reason === "string" ? reason : null, ctx.ifMatch());
  return ok(row, etagged(row));
});

const exceptionDelete = route("delete", "/api/v1/topology/ssids/{ssid}/exceptions/{host}", (ctx) => {
  requireWriter();
  forgetException(hostOfPath(ctx.params.host), ctx.params.ssid, ctx.ifMatch());
  return noContent();
});

export const topologyRoutes: HttpHandler[] = [
  graphRoute,
  nodeRoute,
  rootGet,
  rootPut,
  rootDelete,
  ssidsGet,
  policyPut,
  policyDelete,
  exceptionPut,
  exceptionDelete,
];
