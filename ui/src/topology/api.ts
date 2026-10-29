// The only module of the topology area that talks to the API (docs/topology.md, section 4):
// the graph with its filters, one node with its ports and neighbours, and the sites and VLANs
// of IPAM that the filter bar offers.
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { fetchAll } from "../api/paginate";
import { isApiError } from "../api/problem";

type S = components["schemas"];

export type TopologyGraph = S["TopologyGraph"];
export type TopologyNode = S["TopologyNode"];
export type TopologyEdge = S["TopologyEdge"];
export type TopologySummary = S["TopologySummary"];
export type TopologyNodeView = S["TopologyNodeView"];
export type TopologyPort = S["TopologyPort"];
export type Neighbour = S["Neighbour"];
export type NodeIntent = S["NodeIntent"];
export type IntentAddress = S["IntentAddress"];
export type VlanInView = S["VlanInView"];
export type ControllerStatus = S["ControllerStatus"];
export type NetworkInView = S["NetworkInView"];
export type NetworkDhcp = S["NetworkDhcp"];
export type NodeKind = S["NodeKind"];
export type EdgeKind = S["EdgeKind"];
export type Site = S["Site"];
export type Vlan = S["Vlan"];

/** What narrows the map: the filters of the URL. Kinds are combined with OR, everything else with AND. */
export interface TopologyFilter {
  /** A site identifier. */
  site?: string | undefined;
  /** A VLAN id (1 to 4094) or the identifier of a VLAN object. */
  vlan?: string | undefined;
  kinds: readonly NodeKind[];
  /** Text over label, addresses, vendor, model and SSIDs; empty for none. */
  q: string;
}

/** The graph in view with its summary. */
export function getTopology(filter: TopologyFilter, signal?: AbortSignal): Promise<TopologyGraph> {
  return api.get("/api/v1/topology", {
    query: {
      site: filter.site,
      vlan: filter.vlan,
      kind: filter.kinds.length > 0 ? [...filter.kinds] : undefined,
      q: filter.q || undefined,
    },
    signal,
  });
}

/** One node with its ports and neighbours; with `port`, only that port and what hangs on it. */
export function getNode(id: string, port?: string, signal?: AbortSignal): Promise<TopologyNodeView> {
  return api.get("/api/v1/topology/nodes/{id}", { path: { id }, query: { port }, signal });
}

/** The sites of IPAM, for the site filter. */
export async function listSites(signal?: AbortSignal): Promise<Site[]> {
  return (await fetchAll<Site>("/api/v1/sites", { signal })).items;
}

/** The VLANs of IPAM, for the VLAN filter. */
export async function listVlans(signal?: AbortSignal): Promise<Vlan[]> {
  return (await fetchAll<Vlan>("/api/v1/vlans", { signal })).items;
}

/** Whether an error says that the graph no longer has the node. */
export function isNodeGone(err: unknown): boolean {
  return isApiError(err, "ipam.topology.not_found");
}

// ---------------------------------------------------------------------------------
// The root of the map and the SSID view (U7)

export type MapRoot = S["MapRoot"];
export type RootDecision = S["RootDecision"];
export type RootCandidate = S["RootCandidate"];
export type RootSource = S["RootSource"];
export type SsidView = S["SsidView"];
export type SsidEntry = S["SsidEntry"];
export type SsidVlan = S["SsidVlan"];
export type SsidClient = S["SsidClient"];
export type WlanPolicy = S["WlanPolicy"];
export type RadioBand = S["RadioBand"];
export type Finding = S["Finding"];

/** The root of the map with its candidates and the stored choice. */
export function getRoot(signal?: AbortSignal): Promise<RootDecision> {
  return api.get("/api/v1/topology/root", { signal });
}

/** "Use this": the map follows the candidate of `source`, remembered on the server. */
export function chooseRoot(source: RootSource): Promise<RootDecision> {
  return api.put("/api/v1/topology/root", { body: { source } });
}

/** The SSIDs with their VLANs and clients. */
export function getSsids(signal?: AbortSignal): Promise<SsidView> {
  return api.get("/api/v1/topology/ssids", { signal });
}

/** Whether the WLAN rules read an SSID. */
export function setWlanPolicy(ssid: string, policy: WlanPolicy): Promise<S["StoredWlanPolicy"]> {
  return api.put("/api/v1/topology/ssids/{ssid}/policy", { path: { ssid }, body: { policy } });
}

/** "Keep on this WLAN": the WLAN rules skip the host on the SSID from now on. */
export function keepOnWlan(ssid: string, host: string, reason?: string): Promise<S["WlanException"]> {
  return api.put("/api/v1/topology/ssids/{ssid}/exceptions/{host}", { path: { ssid, host }, body: reason ? { reason } : {} });
}

/** The findings of the topology (the root, the WLAN rules), the most urgent first. */
export async function listTopologyFindings(signal?: AbortSignal): Promise<Finding[]> {
  const page = await api.get("/api/v1/findings", { query: { area: "topology", limit: 1000 }, signal });
  return page.items;
}
