import { describe, expect, it } from "vitest";
import type { EdgeKind, LayoutEdge, LayoutNode, NodeKind } from "./layout";
import { edgesOnPath, pathToRouter, placedPath, shortestPath } from "./path";

function node(id: string, kind: NodeKind): LayoutNode {
  return { id, kind, label: id };
}

function edge(id: string, a: string, b: string, kind: EdgeKind = "lldp"): LayoutEdge {
  return { id, kind, a, b };
}

/**
 * a - b - d, a - c - d, d - e; and a second component f - g.
 *
 *     b
 *   /   \
 * a       d - e        f - g
 *   \   /
 *     c
 */
const EDGES: LayoutEdge[] = [
  edge("e1", "a", "b"),
  edge("e2", "a", "c"),
  edge("e3", "b", "d"),
  edge("e4", "c", "d"),
  edge("e5", "d", "e"),
  edge("e6", "f", "g"),
];

describe("shortestPath", () => {
  it("finds the shortest path including both ends", () => {
    expect(shortestPath(EDGES, "a", "e")).toEqual(["a", "b", "d", "e"]);
    expect(shortestPath(EDGES, "a", "b")).toEqual(["a", "b"]);
  });

  it("follows the edges in either direction", () => {
    expect(shortestPath(EDGES, "e", "a")).toEqual(["e", "d", "b", "a"]);
    expect(shortestPath(EDGES, "g", "f")).toEqual(["g", "f"]);
  });

  it("prefers the neighbour with the smaller id on a tie", () => {
    // a-b-d and a-c-d are equally long.
    expect(shortestPath(EDGES, "a", "d")).toEqual(["a", "b", "d"]);
    expect(shortestPath(EDGES, "d", "a")).toEqual(["d", "b", "a"]);
    // Whatever the edge order.
    expect(shortestPath([...EDGES].reverse(), "a", "d")).toEqual(["a", "b", "d"]);
  });

  it("gives the lexicographically smallest of the shortest paths", () => {
    // Two routes a-z: a-b-x-z and a-c-y-z (and a-b-y-z); the smallest ids win at every step.
    const edges = [
      edge("1", "a", "c"),
      edge("2", "a", "b"),
      edge("3", "c", "y"),
      edge("4", "b", "y"),
      edge("5", "b", "x"),
      edge("6", "x", "z"),
      edge("7", "y", "z"),
    ];
    expect(shortestPath(edges, "a", "z")).toEqual(["a", "b", "x", "z"]);
  });

  it("prefers a shorter path over a smaller id", () => {
    const edges = [edge("1", "a", "b"), edge("2", "b", "c"), edge("3", "c", "z"), edge("4", "a", "y"), edge("5", "y", "z")];
    expect(shortestPath(edges, "a", "z")).toEqual(["a", "y", "z"]);
  });

  it("returns the single node when both ends are the same", () => {
    expect(shortestPath(EDGES, "d", "d")).toEqual(["d"]);
  });

  it("returns null for an unknown id", () => {
    expect(shortestPath(EDGES, "a", "nope")).toBeNull();
    expect(shortestPath(EDGES, "nope", "a")).toBeNull();
    expect(shortestPath(EDGES, "nope", "nope")).toBeNull();
    expect(shortestPath([], "a", "b")).toBeNull();
  });

  it("returns null when there is no path", () => {
    expect(shortestPath(EDGES, "a", "g")).toBeNull();
    expect(shortestPath(EDGES, "f", "e")).toBeNull();
  });

  it("copes with parallel edges and self-loops", () => {
    const edges = [edge("1", "a", "b"), edge("2", "b", "a"), edge("3", "b", "b"), edge("4", "b", "c")];
    expect(shortestPath(edges, "a", "c")).toEqual(["a", "b", "c"]);
  });
});

/** A client and a switch with two routers at the same distance. */
function tieGraph(): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  return {
    nodes: [node("c", "host"), node("sw", "switch"), node("rb", "router"), node("ra", "router")],
    edges: [edge("1", "c", "sw"), edge("2", "sw", "rb"), edge("3", "sw", "ra")],
  };
}

describe("pathToRouter", () => {
  const nodes: LayoutNode[] = [
    node("r1", "router"),
    node("r2", "router"),
    node("sw1", "switch"),
    node("sw2", "switch"),
    node("ap1", "access_point"),
    node("c1", "host"),
    node("c2", "host"),
    node("lone", "host"),
    node("x1", "switch"),
    node("x2", "host"),
  ];
  const edges: LayoutEdge[] = [
    edge("e1", "r2", "sw1", "uplink"),
    edge("e2", "sw1", "c1", "wired"),
    edge("e3", "sw1", "sw2", "uplink"),
    edge("e4", "sw2", "r1", "uplink"),
    edge("e5", "sw2", "ap1", "uplink"),
    edge("e6", "ap1", "c2", "wireless"),
    edge("e7", "x1", "x2", "wired"),
  ];

  it("finds the path from a client to its router", () => {
    expect(pathToRouter(nodes, edges, "c1")).toEqual(["c1", "sw1", "r2"]);
  });

  it("goes to the nearest router, not to the one with the smaller id", () => {
    // From c2 the router r1 is 3 hops away and r2 is 4 hops away.
    expect(pathToRouter(nodes, edges, "c2")).toEqual(["c2", "ap1", "sw2", "r1"]);
    expect(pathToRouter(nodes, edges, "sw1")).toEqual(["sw1", "r2"]);
  });

  it("breaks a tie between two routers by id", () => {
    const tie = tieGraph();
    expect(pathToRouter(tie.nodes, tie.edges, "c")).toEqual(["c", "sw", "ra"]);
    expect(pathToRouter(tie.nodes, [...tie.edges].reverse(), "c")).toEqual(["c", "sw", "ra"]);
  });

  it("returns just the node when it is a router", () => {
    expect(pathToRouter(nodes, edges, "r1")).toEqual(["r1"]);
    expect(pathToRouter(nodes, [], "r2")).toEqual(["r2"]);
  });

  it("returns null when no router is reachable", () => {
    expect(pathToRouter(nodes, edges, "x2")).toBeNull();
    expect(pathToRouter(nodes, edges, "x1")).toBeNull();
    expect(pathToRouter(nodes, edges, "lone")).toBeNull();
  });

  it("returns null for an unknown id", () => {
    expect(pathToRouter(nodes, edges, "nope")).toBeNull();
  });

  it("returns null when the graph has no router at all", () => {
    const switches = nodes.filter((n) => n.kind !== "router");
    expect(pathToRouter(switches, edges, "c1")).toBeNull();
  });

  it("does not walk through a router to the next one", () => {
    const line = [node("r1", "router"), node("sw", "switch"), node("r2", "router"), node("c", "host")];
    const lineEdges = [edge("1", "c", "r2"), edge("2", "r2", "sw"), edge("3", "sw", "r1")];
    expect(pathToRouter(line, lineEdges, "sw")).toEqual(["sw", "r1"]);
    expect(pathToRouter(line, lineEdges, "c")).toEqual(["c", "r2"]);
  });
});

describe("edgesOnPath", () => {
  it("returns the ids of the edges between consecutive nodes", () => {
    expect(edgesOnPath(EDGES, ["a", "b", "d", "e"])).toEqual(new Set(["e1", "e3", "e5"]));
  });

  it("finds an edge whichever way it points", () => {
    expect(edgesOnPath(EDGES, ["e", "d", "c", "a"])).toEqual(new Set(["e5", "e4", "e2"]));
  });

  it("takes the smallest edge id of parallel edges", () => {
    const edges = [edge("z", "a", "b"), edge("m", "b", "a"), edge("q", "a", "b"), edge("n", "b", "c")];
    expect(edgesOnPath(edges, ["a", "b", "c"])).toEqual(new Set(["m", "n"]));
  });

  it("gives an empty set for a path of at most one node", () => {
    expect(edgesOnPath(EDGES, [])).toEqual(new Set());
    expect(edgesOnPath(EDGES, ["a"])).toEqual(new Set());
  });

  it("skips a pair that no edge joins", () => {
    expect(edgesOnPath(EDGES, ["a", "e", "d"])).toEqual(new Set(["e5"]));
  });

  it("matches the path that shortestPath returns", () => {
    const path = shortestPath(EDGES, "a", "e") ?? [];
    expect(edgesOnPath(EDGES, path).size).toBe(path.length - 1);
  });
});

describe("placedPath", () => {
  const hidden = new Map([
    ["h1", "group:sw1"],
    ["h2", "group:sw1"],
    ["h3", "group:sw1"],
  ]);

  it("maps a hidden end to its group", () => {
    expect(placedPath(["h1", "sw1", "r1"], hidden)).toEqual(["group:sw1", "sw1", "r1"]);
    expect(placedPath(["r1", "sw1", "h3"], hidden)).toEqual(["r1", "sw1", "group:sw1"]);
  });

  it("drops consecutive duplicates", () => {
    expect(placedPath(["h1", "h2", "sw1"], hidden)).toEqual(["group:sw1", "sw1"]);
    expect(placedPath(["h1", "h2"], hidden)).toEqual(["group:sw1"]);
  });

  it("keeps a group that is passed twice with other nodes between", () => {
    expect(placedPath(["h1", "sw1", "h2"], hidden)).toEqual(["group:sw1", "sw1", "group:sw1"]);
  });

  it("leaves a path without hidden nodes alone", () => {
    expect(placedPath(["a", "b", "c"], hidden)).toEqual(["a", "b", "c"]);
    expect(placedPath(["a", "b", "c"], new Map())).toEqual(["a", "b", "c"]);
    expect(placedPath([], hidden)).toEqual([]);
  });
});
