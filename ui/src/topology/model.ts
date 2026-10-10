// The words and small rules of the topology views, as pure functions: the names of node and
// edge kinds, their shapes and line classes, the filters as they are written in the URL, which
// VLANs get colors, and the link of a selected node.
import type { IconName } from "../components/Icon";
import { paths, seg } from "../app/paths";
import { t } from "../i18n";
import type { EdgeKind, NodeKind, TopologyFilter, VlanInView } from "./api";

/** Node kinds in the order the filter bar and the legend list them. */
export const NODE_KINDS: readonly NodeKind[] = [
  "router",
  "switch",
  "access_point",
  "hypervisor",
  "vm",
  "container",
  "host",
  "device",
];

/** Edge kinds in the order the legend lists them. */
export const EDGE_KINDS: readonly EdgeKind[] = ["uplink", "wired", "wireless", "lldp", "vm_host"];

/** With this many VLANs in view, only the VLAN chosen in the filter keeps its color (IPAM-20). */
export const VLAN_COLOR_LIMIT = 150;

/** The id prefix the layout gives a group of hidden leaves: `group:<parent id>`. */
export const GROUP_PREFIX = "group:";

export function isGroupId(id: string): boolean {
  return id.startsWith(GROUP_PREFIX);
}

/** The parent whose leaves a group id stands for. */
export function groupParent(id: string): string {
  return isGroupId(id) ? id.slice(GROUP_PREFIX.length) : id;
}

// ---------------------------------------------------------------------------------
// Words, icons, shapes and classes

export function kindWord(kind: NodeKind): string {
  return t(`topology.kind.${kind}`);
}

export function edgeWord(kind: EdgeKind): string {
  return t(`topology.edge.${kind}`);
}

/** The glyph of a kind in the filter bar; the word always comes with it. */
export function kindIcon(kind: NodeKind): IconName {
  switch (kind) {
    case "router":
      return "router";
    case "switch":
      return "cable";
    case "access_point":
      return "wifi";
    case "hypervisor":
      return "server";
    case "vm":
      return "vm";
    case "container":
      return "layers";
    case "host":
      return "terminal";
    case "device":
      return "link";
  }
}

function circle(r: number): string {
  return `M${-r} 0a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0Z`;
}

/**
 * The outline of each kind, centred on (0, 0) and at most 40 x 28 units, so that the shape
 * tells the kind apart without color: a hexagon for a router, a wide box for a switch, a ring
 * for an access point, a framed square for a hypervisor, a small square for a virtual machine,
 * a diamond for a container, a disc for a host and a triangle for any other device. A group of
 * hidden devices is a wide dashed box that holds its count. Drawn with the even-odd fill rule.
 */
export const SHAPES: Readonly<Record<NodeKind | "group", string>> = {
  router: "M-18 0L-9 -14H9L18 0L9 14H-9Z",
  switch: "M-20 -10H20V10H-20Z",
  access_point: circle(13) + circle(5),
  hypervisor: "M-14 -14H14V14H-14ZM-7 -7V7H7V-7Z",
  vm: "M-9 -9H9V9H-9Z",
  container: "M0 -12L12 0L0 12L-12 0Z",
  host: circle(10),
  device: "M0 -13L13 11H-13Z",
  group: "M-40 -12H40V12H-40Z",
};

/** The class of an edge kind: its line style (solid, dashed, dotted, thick, thin) is in topology.css. */
export function edgeClass(kind: EdgeKind): string {
  return `topology-edge edge-${kind}`;
}

/** A label cut to fit under its shape; the full label stays in the accessible name and the tooltip. */
export function shortLabel(label: string, max = 20): string {
  const chars = [...label];
  return chars.length <= max ? label : `${chars.slice(0, max - 1).join("")}…`;
}

/** The accessible name of a node: its label and its kind in words. */
export function nodeAriaLabel(node: { label: string; kind: NodeKind }): string {
  return t("topology.node.aria", { label: node.label, kind: kindWord(node.kind) });
}

const SOURCE_KINDS = ["intent", "network_controller", "probe", "inventory"] as const;
type SourceKind = (typeof SOURCE_KINDS)[number];

/** A source key (`network_controller:<connector>`, `probe:3:snmp`, `intent`) in words. */
export function sourceWord(key: string): string {
  const kind = key.split(":")[0] ?? "";
  return (SOURCE_KINDS as readonly string[]).includes(kind) ? t(`topology.source.${kind as SourceKind}`) : key;
}

/** The link state of a port in words. */
export function portStateWord(up: boolean | null | undefined): string {
  return up === true ? t("topology.port.up") : up === false ? t("topology.port.down") : t("topology.port.unknown");
}

/** The port as the sources name it, with the controller's name when that differs. */
export function portTitle(port: { port: string; name?: string | null | undefined }): string {
  return port.name && port.name !== port.port ? `${port.port} (${port.name})` : port.port;
}

// ---------------------------------------------------------------------------------
// Filters in the URL

/** The query parameters of the page: a value, a repeated value, or none. */
export type QueryValues = Record<string, string | string[] | undefined>;

export const EMPTY_FILTER: TopologyFilter = { site: undefined, vlan: undefined, kinds: [], q: "" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A single value of a query parameter; a repeated parameter counts as absent. */
function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

/** A VLAN id (1 to 4094) as a number, else undefined. */
export function vidOf(value: string | undefined): number | undefined {
  if (value === undefined || !/^\d{1,4}$/.test(value)) return undefined;
  const vid = Number(value);
  return vid >= 1 && vid <= 4094 ? vid : undefined;
}

/**
 * The filter a URL asks for. A site is any identifier, a VLAN is an id of 1 to 4094 or the
 * identifier of a VLAN object, kinds are the known ones (in the order of `NODE_KINDS`, once
 * each), the text is trimmed. Anything else is ignored.
 */
export function parseFilter(search: QueryValues): TopologyFilter {
  const vlan = one(search.vlan);
  const listed = new Set((one(search.kind) ?? "").split(",").map((k) => k.trim()));
  return {
    site: one(search.site),
    vlan: vlan !== undefined && (vidOf(vlan) !== undefined || UUID.test(vlan)) ? vlan : undefined,
    kinds: NODE_KINDS.filter((k) => listed.has(k)),
    q: one(search.q) ?? "",
  };
}

/** The query parameters of a filter, with `undefined` for what is not set (it leaves the URL). */
export function filterParams(filter: TopologyFilter): Record<"site" | "vlan" | "kind" | "q", string | undefined> {
  return {
    site: filter.site || undefined,
    vlan: filter.vlan || undefined,
    kind: filter.kinds.length > 0 ? NODE_KINDS.filter((k) => filter.kinds.includes(k)).join(",") : undefined,
    q: filter.q.trim() || undefined,
  };
}

/** The query string of a filter (`?vlan=30`), empty when nothing is set. */
export function filterSearch(filter: TopologyFilter): string {
  const sp = new URLSearchParams();
  for (const [name, value] of Object.entries(filterParams(filter))) if (value !== undefined) sp.set(name, value);
  const text = sp.toString();
  return text ? `?${text}` : "";
}

/** Whether any filter is set. */
export function isFiltered(filter: TopologyFilter): boolean {
  return !!filter.site || !!filter.vlan || filter.kinds.length > 0 || filter.q !== "";
}

/** A key that changes exactly when the filter does. */
export function filterKey(filter: TopologyFilter): string {
  return filterSearch(filter);
}

/** The kinds with `kind` switched on or off. */
export function toggleKind(kinds: readonly NodeKind[], kind: NodeKind): NodeKind[] {
  return NODE_KINDS.filter((k) => (k === kind ? !kinds.includes(k) : kinds.includes(k)));
}

// ---------------------------------------------------------------------------------
// VLAN colors

/** The VLAN id the filter names, also when it names a VLAN object that is in view. */
export function selectedVid(selected: string | undefined, vlans: readonly VlanInView[]): number | undefined {
  if (selected === undefined) return undefined;
  return vidOf(selected) ?? vlans.find((v) => v.vlan === selected)?.vid;
}

/**
 * The VLAN ids that get a color. Every VLAN in view has one, up to `VLAN_COLOR_LIMIT - 1`
 * VLANs; with that many or more only the VLAN of the filter has one and all others stay
 * neutral (docs/topology.md, section 6). Ascending, once each.
 */
export function vlanColorIds(vlans: readonly VlanInView[], selected: string | undefined): number[] {
  const vids = [...new Set(vlans.map((v) => v.vid))].sort((a, b) => a - b);
  if (vids.length < VLAN_COLOR_LIMIT) return vids;
  const only = selectedVid(selected, vlans);
  return only === undefined ? [] : [only];
}

// ---------------------------------------------------------------------------------
// Links

/** The map with a device selected: `/topology/<id>`, keeping the query string `search`. */
export function topologyPath(id?: string, search = ""): string {
  return `${paths.topology()}${id ? `/${seg(id)}` : ""}${search}`;
}
