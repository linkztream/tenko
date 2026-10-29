import { describe, expect, it } from "vitest";
import {
  isInfrastructure,
  layout,
  type EdgeKind,
  type Layout,
  type LayoutEdge,
  type LayoutNode,
  type NodeKind,
  type PlacedNode,
} from "./layout";

function node(id: string, kind: NodeKind, label = id): LayoutNode {
  return { id, kind, label };
}

function edge(id: string, kind: EdgeKind, a: string, b: string): LayoutEdge {
  return { id, kind, a, b };
}

/** A small deterministic shuffle (Fisher-Yates with a linear congruential generator). */
function shuffled<T>(items: readonly T[], seed: number): T[] {
  const result = [...items];
  let state = seed;
  for (let i = result.length - 1; i > 0; i--) {
    state = (state * 1664525 + 1013904223) % 4294967296;
    const j = state % (i + 1);
    const a = result[i] as T;
    result[i] = result[j] as T;
    result[j] = a;
  }
  return result;
}

function placed(result: Layout, id: string): PlacedNode {
  const found = result.nodes.find((n) => n.id === id);
  if (!found) throw new Error(`no placed node ${id}`);
  return found;
}

function placedEdge(result: Layout, id: string) {
  const found = result.edges.find((e) => e.id === id);
  if (!found) throw new Error(`no placed edge ${id}`);
  return found;
}

function xy(result: Layout, id: string): [number, number] {
  const n = placed(result, id);
  return [n.x, n.y];
}

/**
 * A home lab: the router r1, the switch sw1 and the access point ap1 (which the router sees
 * by LLDP as well), three wired hosts on the switch, two wireless clients on the access
 * point and a hypervisor on the switch with two VMs.
 */
const LAB_NODES: LayoutNode[] = [
  node("r1", "router", "Gateway"),
  node("sw1", "switch", "Core switch"),
  node("ap1", "access_point", "Living room AP"),
  node("h1", "host", "Desktop"),
  node("h2", "host", "NAS"),
  node("h3", "host", "Printer"),
  node("w1", "host", "Phone"),
  node("w2", "host", "Tablet"),
  node("hv1", "hypervisor", "Proxmox"),
  node("vm1", "vm", "Mail"),
  node("vm2", "vm", "Web"),
];
const LAB_EDGES: LayoutEdge[] = [
  edge("e01", "uplink", "r1", "sw1"),
  edge("e02", "uplink", "sw1", "ap1"),
  edge("e03", "wired", "sw1", "h1"),
  edge("e04", "wired", "sw1", "h2"),
  edge("e05", "wired", "sw1", "h3"),
  edge("e06", "wireless", "ap1", "w1"),
  edge("e07", "wireless", "ap1", "w2"),
  edge("e08", "wired", "sw1", "hv1"),
  edge("e09", "vm_host", "hv1", "vm1"),
  edge("e10", "vm_host", "hv1", "vm2"),
  edge("e11", "lldp", "r1", "ap1"),
];

/** A router r1 with a switch sw1 that has `count` hosts h01, h02, ... */
function crowdedSwitch(count: number): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const nodes = [node("r1", "router", "Gateway"), node("sw1", "switch", "Core switch")];
  const edges = [edge("u1", "uplink", "r1", "sw1")];
  for (let i = 1; i <= count; i++) {
    const n = String(i).padStart(2, "0");
    nodes.push(node(`h${n}`, "host", `Host ${n}`));
    edges.push(edge(`w${n}`, "wired", "sw1", `h${n}`));
  }
  return { nodes, edges };
}

describe("isInfrastructure", () => {
  it("is true for routers, switches, access points and unclassified devices only", () => {
    for (const kind of ["router", "switch", "access_point", "device"] as const) {
      expect(isInfrastructure(kind), kind).toBe(true);
    }
    for (const kind of ["hypervisor", "vm", "container", "host", "group"] as const) {
      expect(isInfrastructure(kind), kind).toBe(false);
    }
  });
});

describe("layout of a home lab", () => {
  const result = layout(LAB_NODES, LAB_EDGES);

  it("has one root, the router, at depth 0", () => {
    const roots = result.nodes.filter((n) => n.parent === null);
    expect(roots.map((n) => n.id)).toEqual(["r1"]);
    expect(placed(result, "r1").depth).toBe(0);
  });

  it("lists every node once, sorted by id, and hides none", () => {
    expect(result.nodes.map((n) => n.id)).toEqual([
      "ap1",
      "h1",
      "h2",
      "h3",
      "hv1",
      "r1",
      "sw1",
      "vm1",
      "vm2",
      "w1",
      "w2",
    ]);
    expect(result.hidden.size).toBe(0);
    expect(result.position.size).toBe(11);
    expect(result.position.get("h2")).toBe(placed(result, "h2"));
  });

  it("gives the depth and the parent of the breadth-first spanning tree", () => {
    const tree = Object.fromEntries(result.nodes.map((n) => [n.id, [n.depth, n.parent]]));
    expect(tree).toEqual({
      r1: [0, null],
      sw1: [1, "r1"],
      // The access point is next to the router (LLDP), so it is a child of the router.
      ap1: [1, "r1"],
      hv1: [2, "sw1"],
      h1: [2, "sw1"],
      h2: [2, "sw1"],
      h3: [2, "sw1"],
      w1: [2, "ap1"],
      w2: [2, "ap1"],
      vm1: [3, "hv1"],
      vm2: [3, "hv1"],
    });
  });

  it("places the leaves in a grid below their parent and the branches below the leaf rows", () => {
    // r1 is 5 slots wide (switch 3, access point 2): x = 60 + 5 * 60, no leaves, branches at y = 135.
    expect(xy(result, "r1")).toEqual([360, 45]);
    expect(xy(result, "sw1")).toEqual([240, 135]);
    expect(xy(result, "ap1")).toEqual([540, 135]);
    // The three hosts of the switch fill one row of 3 columns right below it.
    expect(xy(result, "h1")).toEqual([120, 225]);
    expect(xy(result, "h2")).toEqual([240, 225]);
    expect(xy(result, "h3")).toEqual([360, 225]);
    // The hypervisor is a branch: below the leaf row (135 + 2 * 90), two slots wide, left aligned
    // in the three slots of the switch with half a slot of slack.
    expect(xy(result, "hv1")).toEqual([240, 315]);
    expect(xy(result, "vm1")).toEqual([180, 405]);
    expect(xy(result, "vm2")).toEqual([300, 405]);
    // The two wireless clients below the access point.
    expect(xy(result, "w1")).toEqual([480, 225]);
    expect(xy(result, "w2")).toEqual([600, 225]);
  });

  it("sizes the drawing to the right-most centre plus half a slot and the lowest centre plus half a row", () => {
    expect(result.width).toBe(600 + 60);
    expect(result.height).toBe(405 + 45);
  });

  it("flags spanning-tree edges and keeps the extra edge as a curve", () => {
    const flags = Object.fromEntries(result.edges.map((e) => [e.id, e.tree]));
    expect(flags).toEqual({
      e01: true,
      e02: false,
      e03: true,
      e04: true,
      e05: true,
      e06: true,
      e07: true,
      e08: true,
      e09: true,
      e10: true,
      e11: true,
    });
    // The switch to access point link is the one that is not in the tree.
    const extra = placedEdge(result, "e02");
    expect(extra).toMatchObject({ kind: "uplink", from: "sw1", to: "ap1", x1: 240, y1: 135, x2: 540, y2: 135 });
    expect(extra.members).toEqual(["e02"]);
  });

  it("takes the edge coordinates from the placed nodes", () => {
    for (const e of result.edges) {
      const from = placed(result, e.from);
      const to = placed(result, e.to);
      expect([e.x1, e.y1, e.x2, e.y2]).toEqual([from.x, from.y, to.x, to.y]);
    }
    expect(placedEdge(result, "e08")).toMatchObject({ from: "sw1", to: "hv1", kind: "wired", tree: true });
  });

  it("keeps the extra edge between two branches of different parents", () => {
    // A hypervisor with an uplink to each of two switches: one of them is not in the tree.
    const dual = layout(
      [node("r", "router"), node("s1", "switch"), node("s2", "switch"), node("hv", "hypervisor"), node("vm", "vm")],
      [
        edge("a", "uplink", "r", "s1"),
        edge("b", "uplink", "r", "s2"),
        edge("c", "wired", "s1", "hv"),
        edge("d", "wired", "s2", "hv"),
        edge("e", "vm_host", "hv", "vm"),
      ],
    );
    expect(placed(dual, "hv").parent).toBe("s1");
    expect(Object.fromEntries(dual.edges.map((e) => [e.id, e.tree]))).toEqual({
      a: true,
      b: true,
      c: true,
      d: false,
      e: true,
    });
  });
});

describe("layout determinism", () => {
  it("gives the same result for shuffled input", () => {
    const expected = layout(LAB_NODES, LAB_EDGES);
    for (const seed of [1, 2, 3, 4, 5]) {
      const again = layout(shuffled(LAB_NODES, seed), shuffled(LAB_EDGES, seed + 100));
      expect(again).toEqual(expected);
    }
  });

  it("gives the same result for shuffled input with groups and several components", () => {
    const crowd = crowdedSwitch(30);
    const nodes = [...crowd.nodes, node("r2", "router", "Annex"), node("x", "host", "Lone"), node("sw9", "switch", "Spare")];
    const edges = [...crowd.edges, edge("z1", "uplink", "r2", "sw9"), edge("z2", "wired", "sw9", "x")];
    const expected = layout(nodes, edges);
    for (const seed of [7, 8, 9]) {
      expect(layout(shuffled(nodes, seed), shuffled(edges, seed))).toEqual(expected);
    }
  });

  it("does not modify its input", () => {
    const nodes = [...LAB_NODES].reverse();
    const edges = [...LAB_EDGES].reverse();
    layout(nodes, edges);
    expect(nodes.map((n) => n.id)).toEqual([...LAB_NODES].reverse().map((n) => n.id));
    expect(edges.map((e) => e.id)).toEqual([...LAB_EDGES].reverse().map((e) => e.id));
  });
});

describe("layout roots and visiting order", () => {
  it("starts with the routers ordered by label, then id", () => {
    const result = layout(
      [node("r1", "router", "Beta"), node("r2", "router", "Alpha"), node("r3", "router", "Alpha")],
      [],
    );
    // Alpha (r2), Alpha (r3), Beta (r1): slots of 120 px with one empty slot between two roots.
    expect(result.nodes.map((n) => [n.id, n.x])).toEqual([
      ["r1", 600],
      ["r2", 120],
      ["r3", 360],
    ]);
  });

  it("takes a router that another router reaches as a child, not a root", () => {
    const result = layout(
      [node("r1", "router", "A"), node("r2", "router", "B")],
      [edge("e", "uplink", "r1", "r2")],
    );
    expect(placed(result, "r2")).toMatchObject({ parent: "r1", depth: 1 });
  });

  it("roots the infrastructure without a router by descending degree, then label, then id", () => {
    const result = layout(
      [
        node("sa", "switch", "Zed"),
        node("sb", "switch", "Alpha"),
        node("sc", "switch", "Beta"),
        node("a1", "host"),
        node("b1", "host"),
        node("b2", "host"),
        node("c1", "host"),
        node("c2", "host"),
      ],
      [
        edge("e1", "wired", "sa", "a1"),
        edge("e2", "wired", "sb", "b1"),
        edge("e3", "wired", "sb", "b2"),
        edge("e4", "wired", "sc", "c1"),
        edge("e5", "wired", "sc", "c2"),
      ],
    );
    // sb and sc have degree 2 (Alpha before Beta), sa has degree 1.
    const rootOrder = result.nodes.filter((n) => n.parent === null).sort((a, b) => a.x - b.x);
    expect(rootOrder.map((n) => n.id)).toEqual(["sb", "sc", "sa"]);
  });

  it("roots a component without infrastructure at its node of the highest degree", () => {
    const result = layout(
      [node("vm1", "vm"), node("hv", "hypervisor"), node("vm2", "vm")],
      [edge("e1", "vm_host", "hv", "vm1"), edge("e2", "vm_host", "hv", "vm2")],
    );
    expect(placed(result, "hv")).toMatchObject({ parent: null, depth: 0 });
    expect(placed(result, "vm1")).toMatchObject({ parent: "hv", depth: 1 });
  });

  it("visits infrastructure first, then hypervisors, then the rest, each by label", () => {
    const result = layout(
      [
        node("r", "router"),
        node("sw", "switch", "Zed"),
        node("hv", "hypervisor", "Alpha"),
        node("h", "host", "Alpha host"),
        node("swh", "host", "Switch client"),
        node("vm", "vm", "Guest"),
        node("ap", "access_point", "Beta"),
        node("apc", "host", "AP client"),
      ],
      [
        edge("e1", "uplink", "r", "sw"),
        edge("e2", "wired", "r", "hv"),
        edge("e3", "wired", "r", "h"),
        edge("e4", "uplink", "r", "ap"),
        edge("e5", "vm_host", "hv", "vm"),
        edge("e6", "wired", "sw", "swh"),
        edge("e7", "wireless", "ap", "apc"),
      ],
    );
    // The branches of the router are left to right: access point Beta, switch Zed (infrastructure
    // by label), then the hypervisor. The host is a leaf and sits in the grid of the router.
    const branches = ["ap", "sw", "hv"].map((id) => placed(result, id));
    expect(branches[0]?.x).toBeLessThan(branches[1]?.x ?? 0);
    expect(branches[1]?.x).toBeLessThan(branches[2]?.x ?? 0);
    expect(placed(result, "h").y).toBeLessThan(placed(result, "ap").y);
  });
});

describe("layout leaves", () => {
  it("treats a node without children that is not infrastructure as a leaf", () => {
    // The hypervisor has no children here, so it sits in the grid of the switch; the empty
    // switch is infrastructure and stays a branch.
    const result = layout(
      [node("r", "router"), node("sw", "switch"), node("hv", "hypervisor"), node("sw2", "switch")],
      [edge("e1", "uplink", "r", "sw"), edge("e2", "wired", "sw", "hv"), edge("e3", "uplink", "r", "sw2")],
    );
    expect(placed(result, "hv").y).toBe(placed(result, "sw").y + 90);
    expect(placed(result, "sw2").y).toBe(placed(result, "sw").y);
  });

  it("wraps the leaves after leafColumns", () => {
    const crowd = crowdedSwitch(8);
    const result = layout(crowd.nodes, crowd.edges, { leafColumns: 4 });
    const sw = placed(result, "sw1");
    expect(result.width).toBe(placed(result, "h04").x + 60);
    expect(xy(result, "h01")).toEqual([sw.x - 180, sw.y + 90]);
    expect(xy(result, "h04")).toEqual([sw.x + 180, sw.y + 90]);
    expect(xy(result, "h05")).toEqual([sw.x - 180, sw.y + 180]);
    expect(xy(result, "h08")).toEqual([sw.x + 180, sw.y + 180]);
  });

  it("uses the given gaps", () => {
    const result = layout([node("r", "router"), node("h", "host")], [edge("e", "wired", "r", "h")], {
      colGap: 200,
      rowGap: 50,
    });
    expect(xy(result, "r")).toEqual([200, 25]);
    expect(xy(result, "h")).toEqual([200, 75]);
    expect(result.width).toBe(300);
    expect(result.height).toBe(100);
  });

  it("falls back to the defaults for unusable options", () => {
    const crowd = crowdedSwitch(3);
    const odd = layout(crowd.nodes, crowd.edges, { colGap: -5, rowGap: Number.NaN, leafColumns: 0, maxLeaves: Number.NaN });
    expect(odd).toEqual(layout(crowd.nodes, crowd.edges, { leafColumns: 1 }));
    expect(xy(odd, "sw1")[1]).toBe(135);
  });
});

describe("layout groups", () => {
  const crowd = crowdedSwitch(30);

  it("collapses 30 hosts of a switch into one group", () => {
    const result = layout(crowd.nodes, crowd.edges);
    expect(result.nodes.map((n) => n.id)).toEqual(["group:sw1", "r1", "sw1"]);
    const group = placed(result, "group:sw1");
    expect(group).toMatchObject({ kind: "group", label: "", parent: "sw1", depth: 2 });
    expect(group.members).toEqual(Array.from({ length: 30 }, (_, i) => `h${String(i + 1).padStart(2, "0")}`));
    // One column right below the switch.
    expect(xy(result, "sw1")).toEqual([120, 135]);
    expect(xy(result, "group:sw1")).toEqual([120, 225]);
    expect(result.width).toBe(180);
    expect(result.height).toBe(270);
  });

  it("maps every hidden host to the group", () => {
    const result = layout(crowd.nodes, crowd.edges);
    expect(result.hidden.size).toBe(30);
    expect(new Set(result.hidden.values())).toEqual(new Set(["group:sw1"]));
    expect(result.hidden.get("h17")).toBe("group:sw1");
    expect(result.position.get("h17")).toBe(placed(result, "group:sw1"));
    expect(result.position.get("group:sw1")).toBe(placed(result, "group:sw1"));
    expect(result.position.get("sw1")).toBe(placed(result, "sw1"));
  });

  it("merges the 30 edges into one placed edge", () => {
    const result = layout(crowd.nodes, crowd.edges);
    expect(result.edges.map((e) => e.id)).toEqual(["u1", "w01"]);
    const merged = placedEdge(result, "w01");
    expect(merged).toMatchObject({ kind: "wired", from: "sw1", to: "group:sw1", tree: true, x1: 120, y1: 135, x2: 120, y2: 225 });
    expect(merged.members).toEqual(Array.from({ length: 30 }, (_, i) => `w${String(i + 1).padStart(2, "0")}`));
  });

  it("keeps 12 leaves and collapses 13", () => {
    expect(layout(crowdedSwitch(12).nodes, crowdedSwitch(12).edges).hidden.size).toBe(0);
    expect(layout(crowdedSwitch(13).nodes, crowdedSwitch(13).edges).hidden.size).toBe(13);
  });

  it("collapses at the given maxLeaves", () => {
    const small = crowdedSwitch(5);
    expect(layout(small.nodes, small.edges, { maxLeaves: 5 }).hidden.size).toBe(0);
    expect(layout(small.nodes, small.edges, { maxLeaves: 4 }).hidden.size).toBe(5);
  });

  it("shows the 30 hosts in 5 rows of 6 when the switch is expanded", () => {
    const result = layout(crowd.nodes, crowd.edges, { expanded: new Set(["sw1"]) });
    expect(result.hidden.size).toBe(0);
    expect(result.nodes).toHaveLength(32);
    // The switch is 6 slots wide: x = 60 + 6 * 60 = 420; the leaf columns are 120 .. 720.
    expect(xy(result, "sw1")).toEqual([420, 135]);
    for (let i = 0; i < 30; i++) {
      const id = `h${String(i + 1).padStart(2, "0")}`;
      expect(xy(result, id), id).toEqual([120 + (i % 6) * 120, 225 + Math.floor(i / 6) * 90]);
    }
    expect(result.width).toBe(780);
    expect(result.height).toBe(630);
    expect(result.edges).toHaveLength(31);
    expect(result.edges.every((e) => e.members.length === 1 && e.tree)).toBe(true);
  });

  it("expands per parent: other parents still collapse", () => {
    const nodes = [...crowd.nodes, node("sw2", "switch", "Edge switch")];
    const edges = [...crowd.edges, edge("u2", "uplink", "r1", "sw2")];
    for (let i = 1; i <= 20; i++) {
      nodes.push(node(`k${i}`, "host", `Kiosk ${i}`));
      edges.push(edge(`k${i}-e`, "wired", "sw2", `k${i}`));
    }
    const result = layout(nodes, edges, { expanded: new Set(["sw1"]) });
    expect(result.hidden.size).toBe(20);
    expect(placed(result, "group:sw2").members).toHaveLength(20);
    expect(result.nodes.some((n) => n.id === "group:sw1")).toBe(false);
  });

  it("redirects an extra edge of a hidden host to the group", () => {
    const nodes = [...crowd.nodes, node("sw2", "switch", "Edge switch")];
    const edges = [...crowd.edges, edge("u2", "uplink", "r1", "sw2"), edge("x1", "wired", "sw2", "h05")];
    const result = layout(nodes, edges);
    expect(result.hidden.size).toBe(30);
    const extra = placedEdge(result, "x1");
    expect(extra).toMatchObject({ from: "sw2", to: "group:sw1", tree: false, members: ["x1"] });
  });

  it("drops an edge whose two ends are in the same group", () => {
    const result = layout(crowd.nodes, [...crowd.edges, edge("peer", "lldp", "h01", "h02")]);
    expect(result.edges.map((e) => e.id)).toEqual(["u1", "w01"]);
    expect(placedEdge(result, "w01").members).toHaveLength(30);
  });
});

describe("layout edges", () => {
  it("ignores edges with an unknown end and self-loops", () => {
    const result = layout(
      [node("r", "router"), node("h", "host")],
      [edge("e1", "wired", "r", "h"), edge("e2", "wired", "r", "ghost"), edge("e3", "lldp", "r", "r")],
    );
    expect(result.edges.map((e) => e.id)).toEqual(["e1"]);
  });

  it("merges parallel edges between two nodes under the smallest id and its kind", () => {
    const result = layout(
      [node("r", "router"), node("s", "switch")],
      [edge("b", "lldp", "s", "r"), edge("a", "uplink", "r", "s")],
    );
    expect(result.edges).toHaveLength(1);
    expect(result.edges[0]).toMatchObject({ id: "a", kind: "uplink", from: "r", to: "s", members: ["a", "b"], tree: true });
  });

  it("sorts the edges by id", () => {
    const result = layout(LAB_NODES, [...LAB_EDGES].reverse());
    expect(result.edges.map((e) => e.id)).toEqual(LAB_EDGES.map((e) => e.id));
  });
});

describe("layout of several components", () => {
  it("places two disconnected components side by side with one empty slot between them", () => {
    const result = layout(
      [
        node("ra", "router", "A"),
        node("a1", "host", "A1"),
        node("a2", "host", "A2"),
        node("rb", "router", "B"),
        node("b1", "host", "B1"),
        node("b2", "host", "B2"),
        node("b3", "host", "B3"),
      ],
      [
        edge("e1", "wired", "ra", "a1"),
        edge("e2", "wired", "ra", "a2"),
        edge("e3", "wired", "rb", "b1"),
        edge("e4", "wired", "rb", "b2"),
        edge("e5", "wired", "rb", "b3"),
      ],
    );
    // A takes the slots 60 .. 300 (centres 120, 240), the empty slot 300 .. 420, B 420 .. 780.
    expect(xy(result, "a1")).toEqual([120, 135]);
    expect(xy(result, "a2")).toEqual([240, 135]);
    expect(xy(result, "ra")).toEqual([180, 45]);
    expect(xy(result, "b1")).toEqual([480, 135]);
    expect(xy(result, "b3")).toEqual([720, 135]);
    expect(xy(result, "rb")).toEqual([600, 45]);
    expect(result.width).toBe(780);
    expect(result.nodes.filter((n) => n.parent === null).map((n) => n.id).sort()).toEqual(["ra", "rb"]);
  });

  it("places an isolated node as a root of one slot", () => {
    const result = layout([node("r", "router", "A"), node("lone", "host", "Lone")], []);
    expect(xy(result, "r")).toEqual([120, 45]);
    expect(xy(result, "lone")).toEqual([360, 45]);
  });
});

/** An edge with the bucket (a port or an SSID) of a client edge and the inferred flag. */
function bucketed(id: string, kind: EdgeKind, a: string, b: string, bucket?: string, inferred?: boolean): LayoutEdge {
  const result: LayoutEdge = { id, kind, a, b };
  if (bucket !== undefined) result.bucket = bucket;
  if (inferred !== undefined) result.inferred = inferred;
  return result;
}

describe("layout root option", () => {
  it("starts the forest at the named node before any router", () => {
    const nodes = [node("r1", "router", "Beta"), node("r2", "router", "Alpha")];
    expect(placed(layout(nodes, []), "r2").x).toBe(120);
    const result = layout(nodes, [], { root: "r1" });
    expect(placed(result, "r1").x).toBe(120);
    expect(placed(result, "r2").x).toBe(360);
  });

  it("makes a connected switch the root of its component, with the routers below it", () => {
    const result = layout(
      [node("r1", "router", "A"), node("r2", "router", "B"), node("sw", "switch", "Core")],
      [edge("e1", "uplink", "sw", "r1"), edge("e2", "uplink", "sw", "r2")],
      { root: "sw" },
    );
    expect(placed(result, "sw")).toMatchObject({ parent: null, depth: 0 });
    expect(placed(result, "r1")).toMatchObject({ parent: "sw", depth: 1 });
    expect(placed(result, "r2")).toMatchObject({ parent: "sw", depth: 1 });
  });

  it("ignores a root that names no node", () => {
    const nodes = [node("r1", "router", "Beta"), node("r2", "router", "Alpha")];
    expect(layout(nodes, [], { root: "ghost" })).toEqual(layout(nodes, []));
  });
});

describe("layout root candidates among the infrastructure", () => {
  it("does not root an access point that a switch reaches, even with the higher degree", () => {
    const result = layout(
      [
        node("sw", "switch", "Core"),
        node("ap", "access_point", "AP"),
        node("h", "host", "Desktop"),
        node("c1", "host", "Phone"),
        node("c2", "host", "Tablet"),
        node("c3", "host", "Laptop"),
      ],
      [
        edge("e1", "uplink", "sw", "ap"),
        edge("e2", "wired", "sw", "h"),
        edge("e3", "wireless", "ap", "c1"),
        edge("e4", "wireless", "ap", "c2"),
        edge("e5", "wireless", "ap", "c3"),
      ],
    );
    expect(placed(result, "sw")).toMatchObject({ parent: null, depth: 0 });
    expect(placed(result, "ap")).toMatchObject({ parent: "sw", depth: 1 });
  });

  it("still roots an access point that only has clients", () => {
    const result = layout(
      [
        node("sw", "switch", "Core"),
        node("h", "host", "Desktop"),
        node("ap", "access_point", "AP"),
        node("c1", "host", "Phone"),
        node("c2", "host", "Tablet"),
      ],
      [edge("e1", "wired", "sw", "h"), edge("e2", "wireless", "ap", "c1"), edge("e3", "wireless", "ap", "c2")],
    );
    expect(placed(result, "sw").parent).toBeNull();
    expect(placed(result, "ap")).toMatchObject({ parent: null, depth: 0 });
    // The switch component comes first, then the access point.
    expect(placed(result, "sw").x).toBeLessThan(placed(result, "ap").x);
  });

  it("roots a device before an access point", () => {
    const result = layout(
      [node("d", "device", "Unknown"), node("ap", "access_point", "AP"), node("c1", "host"), node("c2", "host")],
      [edge("e1", "wired", "d", "ap"), edge("e2", "wireless", "ap", "c1"), edge("e3", "wireless", "ap", "c2")],
    );
    expect(placed(result, "d").parent).toBeNull();
    expect(placed(result, "ap").parent).toBe("d");
  });
});

describe("layout servers and network devices", () => {
  // The router sees a server on a wired edge; a switch is only reachable through that server.
  const nodes = [node("r", "router", "Gateway"), node("h", "host", "Server"), node("sw", "switch", "Spare switch")];

  it("never makes a host the parent of a switch over a wired edge", () => {
    const result = layout(nodes, [edge("e1", "wired", "r", "h"), edge("e2", "wired", "h", "sw")]);
    expect(placed(result, "h").parent).toBe("r");
    expect(placed(result, "sw")).toMatchObject({ parent: null, depth: 0 });
    // The edge is still drawn, as an extra one.
    expect(placedEdge(result, "e2")).toMatchObject({ from: "h", to: "sw", tree: false });
  });

  it("makes a host the parent of a switch over an lldp edge", () => {
    const result = layout(nodes, [edge("e1", "wired", "r", "h"), edge("e2", "lldp", "h", "sw")]);
    expect(placed(result, "sw")).toMatchObject({ parent: "h", depth: 2 });
    expect(placedEdge(result, "e2").tree).toBe(true);
  });

  it("makes a host the parent of a switch over an uplink edge", () => {
    const result = layout(nodes, [edge("e1", "wired", "r", "h"), edge("e2", "uplink", "h", "sw")]);
    expect(placed(result, "sw")).toMatchObject({ parent: "h", depth: 2 });
  });

  it("does the same for a hypervisor, and a switch still parents a hypervisor over a wired edge", () => {
    const wired = layout(
      [node("r", "router"), node("hv", "hypervisor"), node("sw", "switch"), node("vm", "vm")],
      [edge("e1", "wired", "r", "hv"), edge("e2", "wired", "hv", "sw"), edge("e3", "vm_host", "hv", "vm")],
    );
    expect(placed(wired, "sw").parent).toBeNull();
    expect(placed(wired, "hv").parent).toBe("r");
    const below = layout(
      [node("r", "router"), node("hv", "hypervisor"), node("sw", "switch")],
      [edge("e1", "uplink", "r", "sw"), edge("e2", "wired", "sw", "hv")],
    );
    expect(placed(below, "hv").parent).toBe("sw");
  });

  it("accepts a link in either direction", () => {
    const result = layout(nodes, [edge("e1", "wired", "r", "h"), edge("e2", "lldp", "sw", "h")]);
    expect(placed(result, "sw").parent).toBe("h");
  });
});

describe("layout with collapseEndpoints", () => {
  const base = [node("r", "router", "Gateway"), node("sw", "switch", "Core switch")];
  const hosts = ["a1", "a2", "a3", "b1", "c1", "c2"].map((id) => node(id, "host", id.toUpperCase()));
  const nodes = [...base, ...hosts];
  const edges = [
    edge("u1", "uplink", "r", "sw"),
    bucketed("w-a3", "wired", "sw", "a3", "Port 1"),
    bucketed("w-a1", "wired", "sw", "a1", "Port 1"),
    bucketed("w-a2", "wired", "a2", "sw", "Port 1"),
    bucketed("w-b1", "wired", "sw", "b1", "Port 2"),
    bucketed("w-c2", "wired", "sw", "c2"),
    bucketed("w-c1", "wired", "sw", "c1"),
  ];
  const collapse = { collapseEndpoints: true };

  it("makes one group per bucket with two or more leaves and keeps a single leaf visible", () => {
    const result = layout(nodes, edges, collapse);
    expect(result.nodes.map((n) => n.id)).toEqual(["b1", "group:sw", "group:sw#Port 1", "r", "sw"]);
    expect(placed(result, "group:sw#Port 1")).toMatchObject({ kind: "group", label: "", parent: "sw", depth: 2 });
    expect(placed(result, "group:sw")).toMatchObject({ kind: "group", parent: "sw", depth: 2 });
    expect(placed(result, "b1")).toMatchObject({ kind: "host", parent: "sw" });
    expect(result.hidden.size).toBe(5);
    expect(result.hidden.get("a2")).toBe("group:sw#Port 1");
    expect(result.hidden.get("c1")).toBe("group:sw");
    expect(result.position.get("a3")).toBe(placed(result, "group:sw#Port 1"));
  });

  it("sets the bucket on a bucket group only and sorts the members", () => {
    const result = layout(nodes, edges, collapse);
    expect(placed(result, "group:sw#Port 1").bucket).toBe("Port 1");
    expect(placed(result, "group:sw#Port 1").members).toEqual(["a1", "a2", "a3"]);
    expect(placed(result, "group:sw")).not.toHaveProperty("bucket");
    expect(placed(result, "group:sw").members).toEqual(["c1", "c2"]);
  });

  it("merges the edges of a group into one placed edge", () => {
    const result = layout(nodes, edges, collapse);
    expect(placedEdge(result, "w-a1")).toMatchObject({
      from: "sw",
      to: "group:sw#Port 1",
      tree: true,
      members: ["w-a1", "w-a2", "w-a3"],
    });
    expect(placedEdge(result, "w-b1")).toMatchObject({ from: "sw", to: "b1", members: ["w-b1"] });
  });

  it("places the groups and the single leaf in the grid under the switch in bucket order", () => {
    const result = layout(nodes, edges, collapse);
    const row = ["group:sw", "group:sw#Port 1", "b1"].map((id) => placed(result, id));
    expect(new Set(row.map((n) => n.y)).size).toBe(1);
    expect(row[0]?.x).toBeLessThan(row[1]?.x ?? 0);
    expect(row[1]?.x).toBeLessThan(row[2]?.x ?? 0);
  });

  it("takes the bucket of the first edge by id between a parent and a leaf", () => {
    const result = layout(
      [...base, node("h1", "host"), node("h2", "host")],
      [
        edge("u1", "uplink", "r", "sw"),
        bucketed("x2", "wired", "sw", "h1", "Port 2"),
        bucketed("x1", "wired", "sw", "h1", "Port 1"),
        bucketed("y1", "wired", "sw", "h2", "Port 1"),
      ],
      collapse,
    );
    expect(placed(result, "group:sw#Port 1").members).toEqual(["h1", "h2"]);
    expect(result.nodes.some((n) => n.id === "group:sw#Port 2")).toBe(false);
  });

  it("opens a bucket when its group id is expanded and keeps the others closed", () => {
    const result = layout(nodes, edges, { ...collapse, expanded: new Set(["group:sw#Port 1"]) });
    expect(result.nodes.map((n) => n.id)).toEqual(["a1", "a2", "a3", "b1", "group:sw", "r", "sw"]);
    expect(result.hidden.size).toBe(2);
  });

  it("opens the bare group when its id is expanded", () => {
    const result = layout(nodes, edges, { ...collapse, expanded: new Set(["group:sw"]) });
    expect(result.nodes.map((n) => n.id)).toEqual(["b1", "c1", "c2", "group:sw#Port 1", "r", "sw"]);
  });

  it("opens every bucket of an expanded parent", () => {
    const result = layout(nodes, edges, { ...collapse, expanded: new Set(["sw"]) });
    expect(result.hidden.size).toBe(0);
    expect(result.nodes.map((n) => n.id)).toEqual(["a1", "a2", "a3", "b1", "c1", "c2", "r", "sw"]);
  });

  it("ignores maxLeaves: many buckets of one leaf each stay visible", () => {
    const many = crowdedSwitch(20);
    const spread = many.edges.map((e) => (e.id.startsWith("w") ? { ...e, bucket: `Port ${e.id.slice(1)}` } : e));
    const result = layout(many.nodes, spread, collapse);
    expect(result.hidden.size).toBe(0);
    expect(result.nodes).toHaveLength(22);
  });

  it("collapses a bucket of two even when maxLeaves would allow them", () => {
    const result = layout(nodes, edges, { ...collapse, maxLeaves: 100 });
    expect(result.hidden.size).toBe(5);
  });

  it("keeps the maxLeaves rule when collapseEndpoints is false or absent", () => {
    const crowd = crowdedSwitch(30).edges.map((e) => (e.id.startsWith("w") ? { ...e, bucket: "Port 1" } : e));
    const plain = layout(crowdedSwitch(30).nodes, crowd);
    expect(plain.nodes.map((n) => n.id)).toEqual(["group:sw1", "r1", "sw1"]);
    expect(layout(crowdedSwitch(30).nodes, crowd, { collapseEndpoints: false })).toEqual(plain);
    expect(layout(nodes, edges).hidden.size).toBe(0);
  });

  it("groups the clients of an access point per SSID", () => {
    const result = layout(
      [node("ap", "access_point", "AP"), node("p1", "host"), node("p2", "host"), node("g1", "host"), node("g2", "host")],
      [
        bucketed("e1", "wireless", "ap", "p1", "Home"),
        bucketed("e2", "wireless", "ap", "p2", "Home"),
        bucketed("e3", "wireless", "ap", "g1", "Guest"),
        bucketed("e4", "wireless", "ap", "g2", "Guest"),
      ],
      collapse,
    );
    expect(result.nodes.map((n) => n.id)).toEqual(["ap", "group:ap#Guest", "group:ap#Home"]);
  });
});

describe("layout inferred edges", () => {
  const nodes = [node("r", "router"), node("sw", "switch"), node("h1", "host"), node("h2", "host")];

  it("is false for an edge without the flag", () => {
    const result = layout(nodes, [edge("u1", "uplink", "r", "sw"), edge("w1", "wired", "sw", "h1")]);
    expect(result.edges.map((e) => e.inferred)).toEqual([false, false]);
  });

  it("carries the flag of a single edge", () => {
    const result = layout(nodes, [
      bucketed("u1", "uplink", "r", "sw", undefined, false),
      bucketed("w1", "wired", "sw", "h1", undefined, true),
    ]);
    expect(placedEdge(result, "u1").inferred).toBe(false);
    expect(placedEdge(result, "w1").inferred).toBe(true);
  });

  it("is true for a placed edge when every merged member is inferred", () => {
    const result = layout(
      nodes,
      [
        bucketed("u1", "uplink", "r", "sw"),
        bucketed("w1", "wired", "sw", "h1", "P", true),
        bucketed("w2", "wired", "sw", "h2", "P", true),
      ],
      { collapseEndpoints: true },
    );
    expect(placedEdge(result, "w1")).toMatchObject({ to: "group:sw#P", members: ["w1", "w2"], inferred: true });
  });

  it("is false for a placed edge merged from an inferred and a non-inferred edge", () => {
    const result = layout(
      nodes,
      [
        bucketed("u1", "uplink", "r", "sw"),
        bucketed("w1", "wired", "sw", "h1", "P", true),
        bucketed("w2", "wired", "sw", "h2", "P", false),
      ],
      { collapseEndpoints: true },
    );
    expect(placedEdge(result, "w1")).toMatchObject({ members: ["w1", "w2"], inferred: false });
    // The order of the members does not matter.
    const swapped = layout(
      nodes,
      [
        bucketed("u1", "uplink", "r", "sw"),
        bucketed("w1", "wired", "sw", "h1", "P", false),
        bucketed("w2", "wired", "sw", "h2", "P", true),
      ],
      { collapseEndpoints: true },
    );
    expect(placedEdge(swapped, "w1").inferred).toBe(false);
  });

  it("merges parallel edges the same way", () => {
    const both = layout(nodes, [bucketed("a", "wired", "r", "sw", undefined, true), bucketed("b", "lldp", "r", "sw", undefined, true)]);
    expect(placedEdge(both, "a")).toMatchObject({ members: ["a", "b"], inferred: true });
    const mixed = layout(nodes, [bucketed("a", "wired", "r", "sw", undefined, true), bucketed("b", "lldp", "r", "sw")]);
    expect(placedEdge(mixed, "a")).toMatchObject({ members: ["a", "b"], inferred: false });
  });
});

describe("layout with gatherUnplaced", () => {
  const nodes = [
    node("r", "router", "Gateway"),
    node("h", "host", "Desktop"),
    node("lone", "router", "Spare router"),
    node("sw", "switch", "Spare switch"),
    node("dev", "device", "Unknown device"),
    node("ap", "access_point", "Spare AP"),
    node("hv", "hypervisor", "Spare hypervisor"),
    node("z", "host", "Lone host"),
    node("a", "host", "Another host"),
    node("vm", "vm", "Lone VM"),
    node("ct", "container", "Lone container"),
    node("g", "host", "Only a dangling edge"),
  ];
  const edges = [edge("e1", "wired", "r", "h"), edge("e2", "wired", "g", "ghost"), edge("e3", "lldp", "g", "g")];

  it("lists the isolated non-infrastructure nodes other than hypervisors, sorted, and leaves them out", () => {
    const result = layout(nodes, edges, { gatherUnplaced: true });
    expect(result.unplaced).toEqual(["a", "ct", "g", "vm", "z"]);
    expect(result.nodes.map((n) => n.id)).toEqual(["ap", "dev", "h", "hv", "lone", "r", "sw"]);
    for (const id of result.unplaced) {
      expect(result.position.has(id), id).toBe(false);
      expect(result.hidden.has(id), id).toBe(false);
    }
  });

  it("keeps isolated routers, switches, access points, devices and hypervisors as roots", () => {
    const result = layout(nodes, edges, { gatherUnplaced: true });
    for (const id of ["lone", "sw", "ap", "dev", "hv"]) {
      expect(placed(result, id), id).toMatchObject({ parent: null, depth: 0 });
    }
  });

  it("places everything and lists nothing when the option is false or absent", () => {
    const plain = layout(nodes, edges);
    expect(plain.unplaced).toEqual([]);
    expect(plain.nodes).toHaveLength(nodes.length);
    expect(layout(nodes, edges, { gatherUnplaced: false })).toEqual(plain);
  });

  it("does not leave out a host that has an edge", () => {
    const result = layout([node("a", "host"), node("b", "host")], [edge("e", "lldp", "a", "b")], { gatherUnplaced: true });
    expect(result.unplaced).toEqual([]);
    expect(result.nodes.map((n) => n.id)).toEqual(["a", "b"]);
  });

  it("sizes the drawing without the unplaced nodes", () => {
    const result = layout([node("r", "router"), node("z", "host")], [], { gatherUnplaced: true });
    expect(result.unplaced).toEqual(["z"]);
    // Without the host the router is the only slot: no empty slot and no second root after it.
    expect(xy(result, "r")).toEqual([120, 45]);
    expect(result.width).toBe(180);
    expect(result.height).toBe(90);
  });
});

describe("layout determinism with the new options", () => {
  const nodes = [
    node("r", "router", "Gateway"),
    node("sw", "switch", "Core switch"),
    node("ap", "access_point", "AP"),
    node("hv", "hypervisor", "Proxmox"),
    node("vm1", "vm", "Mail"),
    node("sw2", "switch", "Spare switch"),
    node("srv", "host", "Server"),
    node("lone", "host", "Lone"),
    node("lone2", "host", "Lone 2"),
    ...["a", "b", "c", "d", "e"].map((id) => node(`h-${id}`, "host", `Host ${id}`)),
    ...["x", "y", "z"].map((id) => node(`w-${id}`, "host", `Phone ${id}`)),
  ];
  const edges = [
    bucketed("e01", "uplink", "r", "sw"),
    bucketed("e02", "wired", "sw", "ap", "Port 9", true),
    bucketed("e03", "wired", "sw", "hv", "Port 8"),
    bucketed("e04", "vm_host", "hv", "vm1"),
    bucketed("e05", "wired", "r", "srv", "Port 1", true),
    bucketed("e06", "wired", "srv", "sw2", "Port 2", true),
    bucketed("e07", "wired", "sw", "h-a", "Port 1"),
    bucketed("e08", "wired", "sw", "h-b", "Port 1", true),
    bucketed("e09", "wired", "sw", "h-c", "Port 2"),
    bucketed("e10", "wired", "sw", "h-d", "Port 2", true),
    bucketed("e11", "wired", "sw", "h-e"),
    bucketed("e12", "wireless", "ap", "w-x", "Home"),
    bucketed("e13", "wireless", "ap", "w-y", "Home", true),
    bucketed("e14", "wireless", "ap", "w-z", "Guest"),
  ];

  it("gives the same result for shuffled input", () => {
    const option = { collapseEndpoints: true, gatherUnplaced: true, root: "sw", expanded: new Set(["group:sw#Port 2"]) };
    const expected = layout(nodes, edges, option);
    expect(expected.unplaced).toEqual(["lone", "lone2"]);
    expect(expected.nodes.map((n) => n.id)).toContain("group:sw#Port 1");
    for (const seed of [1, 2, 3, 4, 5, 6]) {
      expect(layout(shuffled(nodes, seed), shuffled(edges, seed + 50), option)).toEqual(expected);
    }
  });

  it("gives the same result for shuffled input without the options", () => {
    const expected = layout(nodes, edges);
    for (const seed of [11, 12, 13]) {
      expect(layout(shuffled(nodes, seed), shuffled(edges, seed + 50))).toEqual(expected);
    }
  });
});

describe("layout of an empty graph", () => {
  it("is empty and has the size of one slot", () => {
    const result = layout([], []);
    expect(result.nodes).toEqual([]);
    expect(result.edges).toEqual([]);
    expect(result.width).toBe(120);
    expect(result.height).toBe(90);
    expect(result.hidden.size).toBe(0);
    expect(result.position.size).toBe(0);
  });

  it("uses the gaps for the minimum size", () => {
    const result = layout([], [], { colGap: 80, rowGap: 40 });
    expect([result.width, result.height]).toEqual([80, 40]);
  });
});

describe("layout of a large graph", () => {
  const CLIENTS = 3000;
  const SWITCHES = 10;
  const ACCESS_POINTS = 10;

  function large(): { nodes: LayoutNode[]; edges: LayoutEdge[]; parents: string[] } {
    const nodes: LayoutNode[] = [node("r0", "router", "Gateway")];
    const edges: LayoutEdge[] = [];
    const parents: string[] = [];
    for (let i = 0; i < SWITCHES; i++) {
      nodes.push(node(`sw${i}`, "switch", `Switch ${i}`));
      edges.push(edge(`up-sw${i}`, "uplink", "r0", `sw${i}`));
      parents.push(`sw${i}`);
    }
    for (let i = 0; i < ACCESS_POINTS; i++) {
      nodes.push(node(`ap${i}`, "access_point", `AP ${i}`));
      edges.push(edge(`up-ap${i}`, "uplink", "r0", `ap${i}`));
      parents.push(`ap${i}`);
    }
    for (let i = 0; i < CLIENTS; i++) {
      const parent = parents[i % parents.length] as string;
      const id = `c${String(i).padStart(4, "0")}`;
      nodes.push(node(id, "host", `Client ${id}`));
      edges.push(edge(`l-${id}`, parent.startsWith("sw") ? "wired" : "wireless", parent, id));
    }
    return { nodes, edges, parents };
  }

  it("lays out 3,000 clients in under 200 ms and hides every client in a group", () => {
    const { nodes, edges, parents } = large();
    const start = performance.now();
    const result = layout(nodes, edges);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(200);

    expect(result.hidden.size).toBe(CLIENTS);
    expect(result.nodes).toHaveLength(1 + parents.length + parents.length);
    for (const parent of parents) {
      const group = placed(result, `group:${parent}`);
      expect(group.members).toHaveLength(CLIENTS / parents.length);
    }
    expect(result.edges).toHaveLength(2 * parents.length);
    expect(result.edges.every((e) => e.tree)).toBe(true);
  });

  it("lays out 3,000 expanded clients in under 200 ms without overlapping nodes", () => {
    const { nodes, edges, parents } = large();
    const start = performance.now();
    const result = layout(nodes, edges, { expanded: new Set(parents) });
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(200);

    expect(result.hidden.size).toBe(0);
    expect(result.nodes).toHaveLength(1 + parents.length + CLIENTS);
    expect(new Set(result.nodes.map((n) => `${n.x},${n.y}`)).size).toBe(result.nodes.length);
    for (const n of result.nodes) {
      expect(n.x).toBeGreaterThan(0);
      expect(n.x).toBeLessThan(result.width);
      expect(n.y).toBeLessThan(result.height);
    }
  });
});
