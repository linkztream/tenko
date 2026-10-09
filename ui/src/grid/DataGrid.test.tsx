import { fireEvent, render, screen, within } from "@solidjs/testing-library";
import { createMemo, createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { selection as statusSelection } from "../shell/status";
import { createGridSelection, DataGrid } from "./DataGrid";
import { dragged } from "./dnd";
import type { Column, SortState } from "./types";

interface Row {
  id: string;
  ip: string;
  name: string;
  free?: boolean;
}

const columns: Column<Row>[] = [
  { id: "ip", header: () => "Address", sort: "ip", width: 140, render: (r) => r.ip, text: (r) => r.ip },
  { id: "name", header: () => "Name", sort: "name", render: (r) => r.name, text: (r) => r.name },
];

function rows(n: number): Row[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `r${i}`,
    ip: `192.0.2.${i % 256}`,
    name: `host-${i}.example.test`,
  }));
}

function table() {
  return screen.getByRole("grid", { name: "Addresses" });
}

function key(k: string, init: KeyboardEventInit = {}) {
  fireEvent.keyDown(table(), { key: k, ...init });
}

describe("DataGrid", () => {
  it("renders a header and rows with test hooks, and passes axe", async () => {
    render(() => <DataGrid id="t1" label="Addresses" columns={columns} rows={rows(3)} rowId={(r) => r.id} rowKey={(r) => r.ip} />);
    expect(screen.getByTestId("grid-t1")).toBeTruthy();
    const body = within(table()).getAllByTestId("row");
    expect(body).toHaveLength(3);
    expect(body[1]?.dataset.key).toBe("192.0.2.1");
    expect(within(body[1] as HTMLElement).getByText("host-1.example.test").closest("td")?.dataset.col).toBe("name");
    expect(screen.getByTestId("grid-foot").textContent).toContain("3 rows");
    expect(await axeViolations(screen.getByTestId("grid-t1"))).toEqual([]);
  });

  it("moves the cell focus with the keys and opens the focused row with Enter", () => {
    const open = vi.fn();
    render(() => <DataGrid id="t2" label="Addresses" columns={columns} rows={rows(5)} rowId={(r) => r.id} onOpen={open} />);
    fireEvent.focus(table());
    expect(table().getAttribute("aria-activedescendant")).toBe("t2-r0-c1");
    key("ArrowDown");
    key("j");
    key("ArrowRight");
    expect(table().getAttribute("aria-activedescendant")).toBe("t2-r2-c2");
    expect(document.getElementById("t2-r2-c2")?.classList.contains("focus")).toBe(true);
    key("Home", { ctrlKey: true });
    expect(table().getAttribute("aria-activedescendant")).toBe("t2-r0-c2");
    key("End", { ctrlKey: true });
    key("Enter");
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ id: "r4" }));
  });

  it("selects with Space, extends with Shift, selects all with Ctrl+A and clears with Esc", () => {
    render(() => <DataGrid id="t3" label="Addresses" columns={columns} rows={rows(6)} rowId={(r) => r.id} />);
    fireEvent.focus(table());
    key(" ");
    key("ArrowDown", { shiftKey: true });
    key("ArrowDown", { shiftKey: true });
    const selected = () => within(table()).getAllByTestId("row").filter((r) => r.getAttribute("aria-selected") === "true");
    expect(selected().map((r) => r.dataset.id)).toEqual(["r0", "r1", "r2"]);
    expect(statusSelection()).toEqual({ selected: 3, total: 6 });
    key("a", { ctrlKey: true });
    expect(selected()).toHaveLength(6);
    expect(screen.getByTestId("grid-foot").textContent).toContain("6 selected");
    key("Escape");
    expect(selected()).toHaveLength(0);
    expect(statusSelection()).toBeNull();
  });

  it("toggles with the row check box and extends with Shift+click; free rows cannot be selected", () => {
    const data: Row[] = [...rows(2), { id: "gap", ip: "192.0.2.6", name: "", free: true }, ...rows(4).slice(2)];
    render(() => (
      <DataGrid
        id="t4"
        label="Addresses"
        columns={columns}
        rows={data}
        rowId={(r) => r.id}
        selectable={(r) => !r.free}
        fullRow={(r) => (r.free ? <span>free</span> : null)}
      />
    ));
    const boxes = screen.getAllByRole("checkbox", { name: /^Select 192/ });
    expect(boxes).toHaveLength(4);
    fireEvent.click(boxes[0] as HTMLElement);
    fireEvent.click(boxes[3] as HTMLElement, { shiftKey: true });
    const gap = within(table()).getAllByTestId("row").find((r) => r.dataset.id === "gap");
    expect(gap?.getAttribute("aria-selected")).toBeNull();
    expect(within(gap as HTMLElement).getByText("free").closest("td")?.colSpan).toBe(2);
    expect(within(table()).getAllByTestId("row").filter((r) => r.getAttribute("aria-selected") === "true")).toHaveLength(4);
  });

  it("asks for the next sort on a header click and on Enter in the header row", () => {
    const [sort, setSort] = createSignal<SortState | null>(null);
    let last: SortState | null = null;
    const onSort = (s: SortState | null) => {
      last = s;
      setSort(s);
    };
    render(() => <DataGrid id="t5" label="Addresses" columns={columns} rows={rows(2)} rowId={(r) => r.id} sort={sort()} onSort={onSort} />);
    fireEvent.click(screen.getByRole("button", { name: "Name" }));
    expect(last).toEqual({ field: "name", desc: false });
    expect(screen.getByRole("columnheader", { name: /Name/ }).getAttribute("aria-sort")).toBe("ascending");
    fireEvent.focus(table());
    key("ArrowUp");
    key("ArrowRight");
    key("Enter");
    expect(last).toEqual({ field: "name", desc: true });
  });

  it("shows the empty state only when loading is done", () => {
    const [loading, setLoading] = createSignal(true);
    render(() => (
      <DataGrid
        id="t6"
        label="Addresses"
        columns={columns}
        rows={[]}
        rowId={(r: Row) => r.id}
        loading={loading()}
        initial={loading()}
        empty={<p>No addresses yet</p>}
      />
    ));
    expect(screen.queryByText("No addresses yet")).toBeNull();
    setLoading(false);
    expect(screen.getByText("No addresses yet")).toBeTruthy();
  });

  it("renders a window of 65,536 rows and filters them under 100 ms", () => {
    const all = rows(65_536);
    const [text, setText] = createSignal("");
    render(() => {
      const visible = createMemo(() => {
        const q = text();
        return q ? all.filter((r) => r.ip.endsWith(q) || r.name.includes(q)) : all;
      });
      return <DataGrid id="t7" label="Addresses" columns={columns} rows={visible()} rowId={(r) => r.id} />;
    });
    expect(within(table()).getAllByTestId("row").length).toBeLessThan(60);
    expect(screen.getByTestId("grid-foot").textContent).toContain("66K rows");
    const started = performance.now();
    setText(".255");
    const elapsed = performance.now() - started;
    expect(within(table()).getAllByTestId("row")[0]?.dataset.id).toBe("r255");
    expect(screen.getByTestId("grid-foot").textContent).toContain("256 rows");
    expect(elapsed).toBeLessThan(100);
  });

  it("lifts the selected rows when one of them is dragged", () => {
    render(() => {
      const data = rows(4);
      const sel = createGridSelection(() => data, (r) => r.id);
      sel.set(["r1", "r2"]);
      return (
        <DataGrid
          id="t8"
          label="Addresses"
          columns={columns}
          rows={data}
          rowId={(r) => r.id}
          selection={sel}
          dragItems={(list) => list.map((r) => ({ kind: "address", id: r.id, label: r.name, ip: r.ip }))}
        />
      );
    });
    const row = within(table()).getAllByTestId("row")[2] as HTMLElement;
    expect(row.getAttribute("draggable")).toBe("true");
    fireEvent.dragStart(row);
    expect(dragged()?.map((d) => d.id)).toEqual(["r1", "r2"]);
    fireEvent.dragEnd(row);
    expect(dragged()).toBeNull();
  });

  it("opens the row menu with Shift+F10 and runs an action", async () => {
    const remove = vi.fn();
    render(() => (
      <DataGrid
        id="t9"
        label="Addresses"
        columns={columns}
        rows={rows(2)}
        rowId={(r) => r.id}
        rowActions={[{ id: "delete", label: () => "Delete", run: remove, danger: true }]}
      />
    ));
    fireEvent.focus(table());
    key("F10", { shiftKey: true });
    const menu = await screen.findByRole("menu");
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Delete" }));
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({ id: "r0" }));
    expect(screen.queryByRole("menu")).toBeNull();
  });
});
