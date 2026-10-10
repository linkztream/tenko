/**
 * Deterministic layout of the topology map.
 *
 * The server sends a graph of nodes and edges. The map draws it as a forest: a breadth-first
 * spanning forest rooted at the routers, laid out row by row. The client leaves of a node sit
 * in a grid right below it and its other children (switches, access points, hypervisors, ...)
 * sit side by side under that grid. A parent with many leaf children shows them as one group
 * unless it is expanded, so a graph of a few thousand clients stays a few dozen shapes.
 *
 * Everything here is a pure function of the graph and the options. The input order never
 * matters: nodes and edges are sorted first, and every tie is broken by label and id with a
 * plain code unit comparison (no locale), so two runs give the same drawing.
 */

export type NodeKind =
  | "router"
  | "switch"
  | "access_point"
  | "hypervisor"
  | "vm"
  | "container"
  | "host"
  | "device";
export type EdgeKind = "wired" | "wireless" | "lldp" | "uplink" | "vm_host";

export interface LayoutNode {
  id: string;
  kind: NodeKind;
  label: string;
}

export interface LayoutEdge {
  id: string;
  kind: EdgeKind;
  a: string;
  b: string;
}

export interface LayoutOptions {
  /** Parents whose leaf children are shown one by one even when there are many. */
  expanded?: ReadonlySet<string>;
  /** More leaf children than this under one parent collapse into a group (default 12). */
  maxLeaves?: number;
  /** Leaf children per row under their parent (default 6). */
  leafColumns?: number;
  /** Horizontal distance between slots in px (default 120). */
  colGap?: number;
  /** Vertical distance between rows in px (default 90). */
  rowGap?: number;
}

export interface PlacedNode {
  /** The node id, or `group:<parentId>` for a group. */
  id: string;
  kind: NodeKind | "group";
  /** For a group: the empty string (the view renders a translated count). */
  label: string;
  /** Centre in px. The top left of the whole drawing is (0, 0) plus a margin of colGap/2 and rowGap/2. */
  x: number;
  y: number;
  /** The row of the node in its tree (roots 0). Leaf rows do not change it. */
  depth: number;
  /** The placed parent id in the spanning tree. */
  parent: string | null;
  /** For a group: the ids of the hidden nodes, sorted. */
  members?: string[];
}

export interface PlacedEdge {
  /** The edge id; an edge merged from several gets the smallest of their ids. */
  id: string;
  kind: EdgeKind;
  /** Placed ids (a group id when an end is hidden). */
  from: string;
  to: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  /** A spanning-tree edge (drawn straight) or an extra one (drawn as a curve by the view). */
  tree: boolean;
  /** The original edge ids this placed edge stands for, sorted. */
  members: string[];
}

export interface Layout {
  /** Sorted by id. */
  nodes: PlacedNode[];
  /** Sorted by id. */
  edges: PlacedEdge[];
  /** The drawing size in px including the margins. */
  width: number;
  height: number;
  /** Hidden node id to its group id. */
  hidden: Map<string, string>;
  /** Placed id to node; a hidden node id maps to the node of its group too. */
  position: Map<string, PlacedNode>;
}

const DEFAULT_MAX_LEAVES = 12;
const DEFAULT_LEAF_COLUMNS = 6;
const DEFAULT_COL_GAP = 120;
const DEFAULT_ROW_GAP = 90;

const INFRASTRUCTURE: ReadonlySet<NodeKind | "group"> = new Set<NodeKind | "group">([
  "router",
  "switch",
  "access_point",
  "device",
]);

/** Network devices that carry the tree: routers, switches, access points and unclassified devices. */
export function isInfrastructure(kind: NodeKind | "group"): boolean {
  return INFRASTRUCTURE.has(kind);
}

/** The working record of a node (or a group) while the layout is computed. */
interface Slot {
  id: string;
  kind: NodeKind | "group";
  label: string;
  depth: number;
  parent: string | null;
  members?: string[];
  /** Distinct nodes joined to this one by a valid edge. */
  neighbours: Set<Slot>;
  /** Tree children in discovery order. */
  children: Slot[];
  /** Whether this is a leaf of its parent (placed in the grid of the parent). */
  leaf: boolean;
  /** Leaf children (a group counts as one) and the other children, both in discovery order. */
  leaves: Slot[];
  branches: Slot[];
  cols: number;
  leafRows: number;
  branchWidth: number;
  /** Width in slots. */
  width: number;
  left: number;
  top: number;
  x: number;
  y: number;
}

function newSlot(id: string, kind: NodeKind | "group", label: string): Slot {
  return {
    id,
    kind,
    label,
    depth: 0,
    parent: null,
    neighbours: new Set(),
    children: [],
    leaf: false,
    leaves: [],
    branches: [],
    cols: 0,
    leafRows: 0,
    branchWidth: 0,
    width: 1,
    left: 0,
    top: 0,
    x: 0,
    y: 0,
  };
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function byLabel(a: Slot, b: Slot): number {
  return compareText(a.label, b.label) || compareText(a.id, b.id);
}

/** Descending degree, then label, then id. */
function byDegree(a: Slot, b: Slot): number {
  return b.neighbours.size - a.neighbours.size || byLabel(a, b);
}

/** Infrastructure first, then hypervisors, then everything else. */
function visitRank(kind: NodeKind | "group"): number {
  return isInfrastructure(kind) ? 0 : kind === "hypervisor" ? 1 : 2;
}

function byVisit(a: Slot, b: Slot): number {
  return visitRank(a.kind) - visitRank(b.kind) || byLabel(a, b);
}

function compareNodes(a: LayoutNode, b: LayoutNode): number {
  return compareText(a.id, b.id) || compareText(a.kind, b.kind) || compareText(a.label, b.label);
}

function compareEdges(a: LayoutEdge, b: LayoutEdge): number {
  return compareText(a.id, b.id) || compareText(a.kind, b.kind) || compareText(a.a, b.a) || compareText(a.b, b.b);
}

function wholeAtLeast(value: number | undefined, fallback: number, minimum: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.floor(value));
}

function positive(value: number | undefined, fallback: number): number {
  return value !== undefined && Number.isFinite(value) && value > 0 ? value : fallback;
}

/** An unambiguous key of an unordered pair of ids. */
function pairKey(a: string, b: string): string {
  const [lo, hi] = a <= b ? [a, b] : [b, a];
  return `${lo.length}:${lo}|${hi}`;
}

/**
 * Lays out the graph (see the module comment). Edges with an unknown end and self-loops are
 * ignored, and so are repeated edge ids. An edge whose two ends map to the same placed node
 * (both hidden in one group) is dropped; edges between the same two placed nodes are merged
 * into one.
 */
export function layout(
  nodes: readonly LayoutNode[],
  edges: readonly LayoutEdge[],
  options: LayoutOptions = {},
): Layout {
  const maxLeaves = wholeAtLeast(options.maxLeaves, DEFAULT_MAX_LEAVES, 0);
  const leafColumns = wholeAtLeast(options.leafColumns, DEFAULT_LEAF_COLUMNS, 1);
  const colGap = positive(options.colGap, DEFAULT_COL_GAP);
  const rowGap = positive(options.rowGap, DEFAULT_ROW_GAP);
  const expanded = options.expanded;

  // 1. Clean input: sorted, unique ids, only edges between two known nodes.
  const slots = new Map<string, Slot>();
  for (const node of [...nodes].sort(compareNodes)) {
    if (!slots.has(node.id)) slots.set(node.id, newSlot(node.id, node.kind, node.label));
  }
  const edgeIds = new Set<string>();
  const kept: LayoutEdge[] = [];
  for (const edge of [...edges].sort(compareEdges)) {
    const a = slots.get(edge.a);
    const b = slots.get(edge.b);
    if (!a || !b || a === b || edgeIds.has(edge.id)) continue;
    edgeIds.add(edge.id);
    a.neighbours.add(b);
    b.neighbours.add(a);
    kept.push(edge);
  }

  // 2. Spanning forest by breadth-first search. `order` holds the searches of the roots one
  // after the other, so a parent always comes before its children.
  const real = [...slots.values()];
  const candidates = [
    ...real.filter((s) => s.kind === "router").sort(byLabel),
    ...real.filter((s) => s.kind !== "router" && isInfrastructure(s.kind)).sort(byDegree),
    ...real.filter((s) => !isInfrastructure(s.kind)).sort(byDegree),
  ];
  const visited = new Set<Slot>();
  const roots: Slot[] = [];
  const order: Slot[] = [];
  for (const root of candidates) {
    if (visited.has(root)) continue;
    visited.add(root);
    roots.push(root);
    let head = order.length;
    order.push(root);
    while (head < order.length) {
      const slot = order[head++] as Slot;
      const fresh = [...slot.neighbours].filter((n) => !visited.has(n)).sort(byVisit);
      for (const next of fresh) {
        visited.add(next);
        next.parent = slot.id;
        next.depth = slot.depth + 1;
        slot.children.push(next);
        order.push(next);
      }
    }
  }

  // 3. Leaves and groups.
  const hidden = new Map<string, string>();
  for (const slot of order) {
    const leaves: Slot[] = [];
    for (const child of slot.children) {
      child.leaf = child.children.length === 0 && !isInfrastructure(child.kind);
      if (child.leaf) leaves.push(child);
      else slot.branches.push(child);
    }
    if (leaves.length > maxLeaves && !expanded?.has(slot.id)) {
      const group = newSlot(`group:${slot.id}`, "group", "");
      group.depth = slot.depth + 1;
      group.parent = slot.id;
      group.leaf = true;
      group.members = leaves.map((leaf) => leaf.id).sort(compareText);
      for (const leaf of leaves) hidden.set(leaf.id, group.id);
      slots.set(group.id, group);
      slot.leaves = [group];
    } else {
      slot.leaves = leaves;
    }
  }

  // 4. Measurement, children before parents. A leaf keeps the width of one slot.
  for (let i = order.length - 1; i >= 0; i--) {
    const slot = order[i] as Slot;
    if (slot.leaf) continue;
    slot.cols = slot.leaves.length ? Math.min(slot.leaves.length, leafColumns) : 0;
    slot.leafRows = slot.leaves.length ? Math.ceil(slot.leaves.length / slot.cols) : 0;
    slot.branchWidth = slot.branches.reduce((sum, branch) => sum + branch.width, 0);
    slot.width = Math.max(1, slot.cols, slot.branchWidth);
  }

  // 5. Placement, parents before children. The roots stand side by side with one empty slot
  // between two of them.
  let cursor = colGap / 2;
  for (const root of roots) {
    root.left = cursor;
    root.top = rowGap / 2;
    cursor += (root.width + 1) * colGap;
  }
  for (const slot of order) {
    if (slot.leaf) continue;
    slot.x = slot.left + (slot.width * colGap) / 2;
    slot.y = slot.top;
    const cols = slot.cols;
    slot.leaves.forEach((leaf, i) => {
      leaf.x = slot.x - (cols * colGap) / 2 + colGap / 2 + (i % cols) * colGap;
      leaf.y = slot.top + rowGap * (1 + Math.floor(i / cols));
    });
    const y0 = slot.top + rowGap * (1 + slot.leafRows);
    let at = slot.left + ((slot.width - slot.branchWidth) * colGap) / 2;
    for (const branch of slot.branches) {
      branch.left = at;
      branch.top = y0;
      at += branch.width * colGap;
    }
  }

  // 6. The placed nodes: everything but the hidden nodes.
  const placed = new Map<string, PlacedNode>();
  let maxX = 0;
  let maxY = 0;
  for (const slot of slots.values()) {
    if (hidden.has(slot.id)) continue;
    const node: PlacedNode = {
      id: slot.id,
      kind: slot.kind,
      label: slot.label,
      x: slot.x,
      y: slot.y,
      depth: slot.depth,
      parent: slot.parent,
    };
    if (slot.members) node.members = [...slot.members];
    placed.set(slot.id, node);
    maxX = Math.max(maxX, slot.x);
    maxY = Math.max(maxY, slot.y);
  }
  const position = new Map<string, PlacedNode>(placed);
  for (const [nodeId, groupId] of hidden) {
    const group = placed.get(groupId);
    if (group) position.set(nodeId, group);
  }

  // 7. The placed edges. `kept` is sorted by id, so the first edge of a pair has the smallest
  // id and `members` comes out sorted.
  const merged = new Map<string, PlacedEdge>();
  for (const edge of kept) {
    const from = hidden.get(edge.a) ?? edge.a;
    const to = hidden.get(edge.b) ?? edge.b;
    if (from === to) continue;
    const key = pairKey(from, to);
    const existing = merged.get(key);
    if (existing) {
      existing.members.push(edge.id);
      continue;
    }
    const start = placed.get(from);
    const end = placed.get(to);
    if (!start || !end) continue;
    merged.set(key, {
      id: edge.id,
      kind: edge.kind,
      from,
      to,
      x1: start.x,
      y1: start.y,
      x2: end.x,
      y2: end.y,
      tree: start.parent === to || end.parent === from,
      members: [edge.id],
    });
  }

  return {
    nodes: [...placed.values()].sort((a, b) => compareText(a.id, b.id)),
    edges: [...merged.values()].sort((a, b) => compareText(a.id, b.id)),
    width: Math.max(colGap, maxX + colGap / 2),
    height: Math.max(rowGap, maxY + rowGap / 2),
    hidden,
    position,
  };
}
