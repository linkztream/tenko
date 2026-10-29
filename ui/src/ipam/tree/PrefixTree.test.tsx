import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IPAM_IDS } from "../../api/mock/ipam/api";
import type { TreeNode } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { signInAlex } from "../../auth/account/testkit";
import { endDrag, startDrag } from "../../grid/dnd";
import type { TreeResponse } from "../../api/types";
import { filterTree, PrefixTree, resetTreeStateForTest, SPRING_OPEN_MS, useTree } from "./PrefixTree";

function Tree(props: { onOpen?: (n: TreeNode) => void; onDrop?: (n: TreeNode) => void; filter?: string }) {
  const tree = useTree(() => IPAM_IDS.vrf.default);
  return (
    <PrefixTree
      tree={tree.tree()}
      error={tree.error()}
      onOpen={props.onOpen ?? (() => {})}
      onDrop={props.onDrop}
      filter={props.filter}
    />
  );
}

async function nodes() {
  const tree = await screen.findByRole("tree", { name: "Networks" });
  await waitFor(() => expect(within(tree).getAllByRole("treeitem").length).toBeGreaterThan(3));
  return tree;
}

const node = (tree: HTMLElement, cidr: string) => {
  const el = within(tree)
    .getAllByRole("treeitem")
    .find((n) => n.dataset.key === cidr);
  if (!el) throw new Error(`no node ${cidr}`);
  return el;
};

beforeEach(async () => {
  resetTreeStateForTest();
  await signInAlex();
});

const keysOf = (tree: HTMLElement) =>
  within(tree)
    .getAllByRole("treeitem")
    .map((n) => n.dataset.key);

/** A supernet with `count` IPv6 networks, a second top-level network, as the tree endpoint answers. */
function bigTree(count: number): TreeResponse {
  const use = { capacity: "18446744073709551616", in_use: "1", used: "1", reserved: "0", free: "0", covered: "0", size: "0", percent: 0, by_role: [] };
  const node = (id: string, cidr: string, parent: string | null, depth: number, children: number, role: "supernet" | "network") =>
    ({ id, cidr, parent, depth, children, role, status: "active", level: "normal", utilization: use }) as unknown as TreeNode;
  const nodes = [node("s", "2001:db8::/48", null, 0, count, "supernet")];
  for (let i = 0; i < count; i++) nodes.push(node(`n${i}`, `2001:db8:0:${i.toString(16)}::/64`, "s", 1, 0, "network"));
  nodes.push(node("t", "2001:db8:1::/64", null, 0, 0, "network"));
  return { nodes, revision: 1, vrf: "v-big" } as unknown as TreeResponse;
}

describe("prefix tree", () => {
  it("shows the prefixes of the VRF in pre-order with levels, utilization and alarms", async () => {
    render(() => <Tree />);
    const tree = await nodes();
    // The children of a supernet stay closed until the person opens it.
    expect(keysOf(tree)).not.toContain("203.0.113.0/25");
    const supernet = node(tree, "203.0.113.0/24");
    expect(supernet.getAttribute("aria-expanded")).toBe("false");
    expect(within(supernet).getByTestId("tree-child-count").textContent).toMatch(/^\d+$/);
    fireEvent.click(supernet.querySelector(".tw") as HTMLElement);
    await waitFor(() => expect(keysOf(tree)).toContain("203.0.113.0/25"));
    const keys = keysOf(tree);
    expect(keys.indexOf("203.0.113.0/24")).toBeLessThan(keys.indexOf("203.0.113.0/25"));
    expect(node(tree, "203.0.113.0/25").getAttribute("aria-level")).toBe("2");
    const cameras = node(tree, "203.0.113.192/28");
    expect(within(cameras).getAllByText("Critical").length).toBeGreaterThan(0);
    expect(cameras.querySelector(".meter.crit")).toBeTruthy();
    expect(await axeViolations(tree)).toEqual([]);
  });

  it("moves with the arrow keys, closes and opens a supernet, and opens a prefix with Enter", async () => {
    const opened = vi.fn();
    render(() => <Tree onOpen={opened} />);
    const tree = await nodes();
    fireEvent.focus(tree);
    const first = tree.getAttribute("aria-activedescendant");
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    expect(tree.getAttribute("aria-activedescendant")).not.toBe(first);
    // Select the supernet 203.0.113.0/24: nothing unfolds; Right opens it, Left closes it.
    const supernet = node(tree, "203.0.113.0/24");
    fireEvent.click(supernet.querySelector(".tnode") as HTMLElement);
    expect(opened).toHaveBeenLastCalledWith(expect.objectContaining({ cidr: "203.0.113.0/24" }));
    expect(supernet.getAttribute("aria-expanded")).toBe("false");
    fireEvent.keyDown(tree, { key: "ArrowRight" });
    await waitFor(() => expect(node(tree, "203.0.113.0/25")).toBeTruthy());
    expect(supernet.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(tree, { key: "ArrowLeft" });
    await waitFor(() => expect(keysOf(tree)).not.toContain("203.0.113.0/25"));
    expect(supernet.getAttribute("aria-expanded")).toBe("false");
    fireEvent.keyDown(tree, { key: "ArrowRight" });
    await waitFor(() => expect(node(tree, "203.0.113.0/25")).toBeTruthy());
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    fireEvent.keyDown(tree, { key: "Enter" });
    expect(opened).toHaveBeenLastCalledWith(expect.objectContaining({ cidr: "203.0.113.0/25" }));
  });

  it("keeps the matches of a filter with their ancestors", async () => {
    render(() => <Tree filter="cameras" />);
    const tree = await screen.findByRole("tree");
    await waitFor(() =>
      expect(within(tree).getAllByRole("treeitem").map((n) => n.dataset.key)).toEqual(["203.0.113.0/24", "203.0.113.192/28"]),
    );
  });

  it("accepts a drop on a network and refuses a supernet", async () => {
    const dropped = vi.fn();
    render(() => <Tree onDrop={dropped} />);
    const tree = await nodes();
    startDrag([{ kind: "host", id: "h1", label: "thermostat-1", ip: "192.0.2.41" }]);
    const supernet = node(tree, "203.0.113.0/24").querySelector(".tnode") as HTMLElement;
    vi.useFakeTimers();
    fireEvent.dragOver(supernet);
    expect(supernet.classList.contains("dim")).toBe(true);
    expect(supernet.getAttribute("title")).toMatch(/not on a supernet/);
    // Holding the drag on the closed supernet opens it, so its networks can take the drop.
    vi.advanceTimersByTime(SPRING_OPEN_MS + 10);
    vi.useRealTimers();
    await waitFor(() => expect(node(tree, "203.0.113.0/24").getAttribute("aria-expanded")).toBe("true"));
    fireEvent.drop(supernet);
    expect(dropped).not.toHaveBeenCalled();
    const iot = node(tree, "198.51.100.0/24").querySelector(".tnode") as HTMLElement;
    fireEvent.dragOver(iot);
    expect(iot.classList.contains("drop")).toBe(true);
    expect(screen.getByRole("status").textContent).toMatch(/Release to preview moving 1 object to 198.51.100.0\/24/);
    fireEvent.drop(iot);
    expect(dropped).toHaveBeenCalledWith(expect.objectContaining({ cidr: "198.51.100.0/24" }), expect.anything());
    endDrag();
  });

  it("stays short with 150 subnets: nothing unfolds by itself, not even for the selection", () => {
    const tree = bigTree(150);
    render(() => <PrefixTree tree={tree} selectedId="n42" onOpen={() => {}} />);
    const list = screen.getByRole("tree");
    expect(keysOf(list)).toEqual(["2001:db8::/48", "2001:db8:1::/64"]);
    const supernet = node(list, "2001:db8::/48");
    expect(supernet.getAttribute("aria-label")).toBe("2001:db8::/48, 150 child prefixes");
    expect(within(supernet).getByTestId("tree-child-count").textContent).toBe("150");
    // The selected network lies inside the closed supernet: the supernet shows it and is active.
    expect(supernet.querySelector(".tnode")?.classList.contains("holds-selection")).toBe(true);
    expect(list.getAttribute("aria-activedescendant")).toBe("tree-s");
    expect(within(list).queryAllByRole("treeitem", { selected: true })).toHaveLength(0);
    // Opened by the person, it lists its 150 networks; the open state survives a new mount.
    fireEvent.click(supernet.querySelector(".tw") as HTMLElement);
    expect(within(list).getAllByRole("treeitem")).toHaveLength(152);
    expect(within(list).getAllByRole("treeitem", { selected: true })[0]?.dataset.key).toBe("2001:db8:0:2a::/64");
  });

  it("keeps the open nodes of a VRF for the session", () => {
    const tree = bigTree(3);
    const first = render(() => <PrefixTree tree={tree} onOpen={() => {}} />);
    fireEvent.click(node(screen.getByRole("tree"), "2001:db8::/48").querySelector(".tw") as HTMLElement);
    expect(keysOf(screen.getByRole("tree"))).toHaveLength(5);
    first.unmount();
    render(() => <PrefixTree tree={tree} onOpen={() => {}} />);
    expect(keysOf(screen.getByRole("tree"))).toHaveLength(5);
  });

  it("filters a flat list down to the matches and their parents", () => {
    const n = (id: string, cidr: string, parent: string | null, description?: string) =>
      ({ id, cidr, parent, description, depth: 0, children: 0 }) as unknown as TreeNode;
    const list = [n("a", "203.0.113.0/24", null), n("b", "203.0.113.0/25", "a", "Lab"), n("c", "192.0.2.0/24", null, "LAN")];
    expect(filterTree(list, "lab").map((x) => x.id)).toEqual(["a", "b"]);
    expect(filterTree(list, "").map((x) => x.id)).toEqual(["a", "b", "c"]);
  });
});
