// The node choice the query log and the cache view share: the first node until another is chosen,
// the choice kept when the page that made it is gone, and the first node again when the chosen
// one is no longer listed.
import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { Show } from "solid-js";
import { describe, expect, it, vi } from "vitest";

const listed = vi.hoisted(() => ({ ids: [1, 2, 3] }));
vi.mock("./log/api", () => ({ logNodes: () => Promise.resolve(listed.ids) }));

import { NodeSelect, useDnsNode } from "./node";

function Page() {
  const { nodes, node, choose } = useDnsNode();
  // As the pages do: the select appears with its options.
  return (
    <Show when={nodes.latest?.length}>
      <NodeSelect nodes={nodes.latest ?? []} node={node()} onChoose={choose} />
    </Show>
  );
}

function selected(): string {
  return (screen.getByTestId("field-node") as HTMLSelectElement).value;
}

describe("the node choice of the DNS pages", () => {
  it("keeps the node chosen on one page for the next page", async () => {
    const first = render(() => <Page />);
    await waitFor(() => expect(selected()).toBe("1"));
    fireEvent.change(screen.getByTestId("field-node"), { target: { value: "2" } });
    await waitFor(() => expect(selected()).toBe("2"));
    first.unmount();

    render(() => <Page />);
    await waitFor(() => expect(screen.queryAllByRole("option")).toHaveLength(3));
    expect(selected()).toBe("2");
  });

  it("falls back to the first node when the chosen one is no longer listed", async () => {
    listed.ids = [1, 3];
    render(() => <Page />);
    await waitFor(() => expect(screen.queryAllByRole("option")).toHaveLength(2));
    expect(selected()).toBe("1");
  });
});
