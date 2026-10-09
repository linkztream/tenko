import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IPAM_IDS } from "../../api/mock/ipam/api";
import type { TreeNode } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { signInAlex } from "../../auth/account/testkit";
import { endDrag, startDrag } from "../../grid/dnd";
import { filterTree, PrefixTree, useTree } from "./PrefixTree";

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
  await signInAlex();
});

describe("prefix tree", () => {
  it("shows the prefixes of the VRF in pre-order with levels, utilization and alarms", async () => {
    render(() => <Tree />);
    const tree = await nodes();
    const keys = within(tree)
      .getAllByRole("treeitem")
      .map((n) => n.dataset.key);
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
    // Walk to the supernet 203.0.113.0/24 and close it.
    const supernet = node(tree, "203.0.113.0/24");
    fireEvent.click(supernet.querySelector(".tnode") as HTMLElement);
    expect(opened).toHaveBeenLastCalledWith(expect.objectContaining({ cidr: "203.0.113.0/24" }));
    fireEvent.keyDown(tree, { key: "ArrowLeft" });
    await waitFor(() => expect(within(tree).queryAllByRole("treeitem").some((n) => n.dataset.key === "203.0.113.0/25")).toBe(false));
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
    fireEvent.dragOver(supernet);
    expect(supernet.classList.contains("dim")).toBe(true);
    expect(supernet.getAttribute("title")).toMatch(/not on a supernet/);
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

  it("filters a flat list down to the matches and their parents", () => {
    const n = (id: string, cidr: string, parent: string | null, description?: string) =>
      ({ id, cidr, parent, description, depth: 0, children: 0 }) as unknown as TreeNode;
    const list = [n("a", "203.0.113.0/24", null), n("b", "203.0.113.0/25", "a", "Lab"), n("c", "192.0.2.0/24", null, "LAN")];
    expect(filterTree(list, "lab").map((x) => x.id)).toEqual(["a", "b"]);
    expect(filterTree(list, "").map((x) => x.id)).toEqual(["a", "b", "c"]);
  });
});
