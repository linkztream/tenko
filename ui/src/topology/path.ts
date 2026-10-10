/**
 * Paths over the topology graph: the shortest way between two nodes, the way from a node to
 * the nearest router and the edges that lie on a path. Edges are undirected here. Every tie
 * is broken by the smaller id, so the same graph always gives the same path.
 */
import type { LayoutEdge, LayoutNode } from "./layout";

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Every node that appears in an edge, with its distinct neighbours. A self-loop adds the node only. */
function adjacency(edges: readonly LayoutEdge[]): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  const neighbours = (id: string): Set<string> => {
    let set = adj.get(id);
    if (!set) {
      set = new Set();
      adj.set(id, set);
    }
    return set;
  };
  for (const edge of edges) {
    const a = neighbours(edge.a);
    const b = neighbours(edge.b);
    if (edge.a === edge.b) continue;
    a.add(edge.b);
    b.add(edge.a);
  }
  return adj;
}

/** The path from the start of a breadth-first search to `end`, following the parent links. */
function unwind(parent: ReadonlyMap<string, string | null>, end: string): string[] {
  const path: string[] = [];
  for (let at: string | null | undefined = end; at !== null && at !== undefined; at = parent.get(at)) path.push(at);
  return path.reverse();
}

/**
 * The shortest path from `from` to `to` over edges in either direction, as node ids including
 * both ends; null when there is none or an id is unknown (it appears in no edge). Among equally
 * short paths the one whose ids are smallest from the start on wins: the search visits the
 * neighbours of a node by ascending id.
 */
export function shortestPath(edges: readonly LayoutEdge[], from: string, to: string): string[] | null {
  const adj = adjacency(edges);
  if (!adj.has(from) || !adj.has(to)) return null;
  if (from === to) return [from];

  const parent = new Map<string, string | null>([[from, null]]);
  const queue: string[] = [from];
  for (let head = 0; head < queue.length; head++) {
    const id = queue[head] as string;
    for (const next of [...(adj.get(id) ?? [])].sort(compareText)) {
      if (parent.has(next)) continue;
      parent.set(next, id);
      if (next === to) return unwind(parent, to);
      queue.push(next);
    }
  }
  return null;
}

/**
 * The shortest path from `from` to the nearest node of kind `router` (ties by the smaller
 * router id, then as in `shortestPath`); null when no router is reachable or `from` is
 * unknown; `[from]` when `from` is a router.
 */
export function pathToRouter(
  nodes: readonly LayoutNode[],
  edges: readonly LayoutEdge[],
  from: string,
): string[] | null {
  const routers = new Set<string>();
  const known = new Set<string>();
  for (const node of nodes) {
    known.add(node.id);
    if (node.kind === "router") routers.add(node.id);
  }
  if (routers.has(from)) return [from];

  const adj = adjacency(edges);
  if (!known.has(from) && !adj.has(from)) return null;

  const parent = new Map<string, string | null>([[from, null]]);
  const dist = new Map<string, number>([[from, 0]]);
  const queue: string[] = [from];
  let best: string | null = null;
  let bestDist = Infinity;
  for (let head = 0; head < queue.length; head++) {
    const id = queue[head] as string;
    const d = dist.get(id) ?? 0;
    // Everything found from here on is farther than the router already found.
    if (d >= bestDist) break;
    for (const next of [...(adj.get(id) ?? [])].sort(compareText)) {
      if (parent.has(next)) continue;
      parent.set(next, id);
      dist.set(next, d + 1);
      queue.push(next);
      if (routers.has(next) && (best === null || (d + 1 === bestDist && compareText(next, best) < 0))) {
        best = next;
        bestDist = d + 1;
      }
    }
  }
  return best === null ? null : unwind(parent, best);
}

/** An unambiguous key of an unordered pair of ids. */
function pairKey(a: string, b: string): string {
  const [lo, hi] = a <= b ? [a, b] : [b, a];
  return `${lo.length}:${lo}|${hi}`;
}

/** The ids of the edges that join consecutive nodes of a path (the smallest edge id per consecutive pair). */
export function edgesOnPath(edges: readonly LayoutEdge[], path: readonly string[]): Set<string> {
  const wanted = new Set<string>();
  for (let i = 1; i < path.length; i++) {
    const a = path[i - 1];
    const b = path[i];
    if (a === undefined || b === undefined || a === b) continue;
    wanted.add(pairKey(a, b));
  }
  if (wanted.size === 0) return new Set();

  const smallest = new Map<string, string>();
  for (const edge of edges) {
    const key = pairKey(edge.a, edge.b);
    if (!wanted.has(key)) continue;
    const current = smallest.get(key);
    if (current === undefined || edge.id < current) smallest.set(key, edge.id);
  }
  return new Set(smallest.values());
}

/**
 * The path to show when some of its nodes are hidden in groups: every node id of `path` is
 * mapped through `hidden` (an id that is not in `hidden` stays) and consecutive duplicates
 * are dropped.
 */
export function placedPath(path: readonly string[], hidden: ReadonlyMap<string, string>): string[] {
  const result: string[] = [];
  for (const id of path) {
    const placed = hidden.get(id) ?? id;
    if (result[result.length - 1] !== placed) result.push(placed);
  }
  return result;
}
