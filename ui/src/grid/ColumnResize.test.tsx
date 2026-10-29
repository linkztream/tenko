import { fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { DataGrid } from "./DataGrid";
import { FilterBar } from "./FilterBar";
import { tableLayout } from "./layoutStore";
import { createColumnState } from "./prefs";
import type { Column } from "./types";
import { BIG_STEP, DEFAULT_WIDTH, MIN_WIDTH, NARROW_QUERY, STEP, widthsKey, writeWidths } from "./widths";

interface Row {
  id: string;
  ip: string;
  name: string;
  type: string;
}

const columns: Column<Row>[] = [
  { id: "ip", header: () => "Address", sort: "ip", width: 140, render: (r) => r.ip, text: (r) => r.ip },
  { id: "name", header: () => "Name", render: (r) => r.name },
  { id: "type", header: () => "Type", width: 90, render: (r) => r.type },
];

const ROWS: Row[] = [
  { id: "r0", ip: "192.0.2.1", name: "a.example.test", type: "A" },
  { id: "r1", ip: "192.0.2.200", name: "printer-on-the-third-floor.example.test", type: "AAAA" },
];

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function grid(id: string, props: { dir?: "rtl" } = {}) {
  return render(() => (
    <div dir={props.dir}>
      <DataGrid id={id} label="Addresses" columns={columns} rows={ROWS} rowId={(r) => r.id} onSort={() => {}} />
    </div>
  ));
}

const table = () => screen.getByRole("grid", { name: "Addresses" });
const handle = (column: string) => screen.getByRole("separator", { name: `Resize column ${column}` });
/** The `<col>` widths of the data columns (after the selection column). */
const colWidths = () => Array.from(table().querySelectorAll("col")).slice(1).map((c) => (c as HTMLElement).style.width);
/** The widths the layout store holds for the list (seeded through the older browser key, which it imports). */
const stored = (id: string) => tableLayout(undefined, id)()?.widths ?? null;

function drag(el: HTMLElement, from: number, to: number, pointerType = "mouse") {
  fireEvent.pointerDown(el, { clientX: from, pointerId: 1, pointerType, button: 0 });
  fireEvent.pointerMove(el, { clientX: (from + to) / 2, pointerId: 1, pointerType });
  fireEvent.pointerMove(el, { clientX: to, pointerId: 1, pointerType });
  fireEvent.pointerUp(el, { clientX: to, pointerId: 1, pointerType });
}

function tap(el: HTMLElement) {
  fireEvent.pointerDown(el, { clientX: 50, pointerId: 2, pointerType: "touch" });
  fireEvent.pointerUp(el, { clientX: 50, pointerId: 2, pointerType: "touch" });
}

/** Lays out text as 7 px per character, so fitting to content has something to measure. */
function measureText() {
  vi.spyOn(document, "createRange").mockImplementation(() => {
    let text = "";
    return {
      selectNodeContents(node: Node) {
        text = node.textContent ?? "";
      },
      getBoundingClientRect: () => ({ left: 0, right: text.length * 7, width: text.length * 7 }) as DOMRect,
    } as unknown as Range;
  });
}

describe("column resizing in the data grid", () => {
  it("offers a named handle per column, only the focused column's in the tab order, and passes axe", async () => {
    grid("rz1");
    const handles = within(table()).getAllByRole("separator");
    expect(handles).toHaveLength(3);
    expect(handle("Address").getAttribute("aria-orientation")).toBe("vertical");
    expect(handle("Address").getAttribute("aria-valuenow")).toBe("140");
    expect(handle("Address").getAttribute("aria-valuemin")).toBe(String(MIN_WIDTH));
    // The column header keeps its own name.
    expect(screen.getByRole("columnheader", { name: "Address" })).toBeTruthy();
    expect(handles.map((h) => h.tabIndex)).toEqual([0, -1, -1]);
    fireEvent.focus(table());
    fireEvent.keyDown(table(), { key: "ArrowRight" });
    expect(handles.map((h) => h.tabIndex)).toEqual([-1, 0, -1]);
    expect(await axeViolations(screen.getByTestId("grid-rz1"))).toEqual([]);
  });

  it("follows a pointer drag, fixes the other columns and lets the last one take the rest", () => {
    grid("rz2");
    expect(colWidths()).toEqual(["140px", "", "90px"]);
    drag(handle("Address"), 100, 160);
    // Address grew by 60; Name was fixed at its width; Type, the last, takes what is left.
    expect(colWidths()).toEqual(["200px", `${DEFAULT_WIDTH}px`, ""]);
    expect(stored("rz2")).toEqual({ ip: 200, name: DEFAULT_WIDTH });
    // The table is at least as wide as its columns (selection 34 + 200 + 160 + last 90).
    expect(table().style.width).toBe(`max(100%, ${34 + 200 + DEFAULT_WIDTH + 90}px)`);
    // A drag never sorts.
    expect(screen.getByRole("columnheader", { name: "Address" }).getAttribute("aria-sort")).toBe("none");
  });

  it("does not go below the minimum width, also by touch", () => {
    grid("rz3");
    drag(handle("Address"), 300, 0, "touch");
    expect(colWidths()[0]).toBe(`${MIN_WIDTH}px`);
  });

  it("mirrors the drag right to left", () => {
    grid("rz4", { dir: "rtl" });
    drag(handle("Address"), 300, 260);
    expect(colWidths()[0]).toBe("180px");
  });

  it("resizes with the arrow keys, further with Shift, and gives the focus back on Enter or Escape", () => {
    grid("rz5");
    const h = handle("Address");
    h.focus();
    fireEvent.keyDown(h, { key: "ArrowRight" });
    expect(colWidths()[0]).toBe(`${140 + STEP}px`);
    fireEvent.keyDown(h, { key: "ArrowRight", shiftKey: true });
    expect(colWidths()[0]).toBe(`${140 + STEP + BIG_STEP}px`);
    fireEvent.keyDown(h, { key: "ArrowLeft" });
    expect(colWidths()[0]).toBe(`${140 + BIG_STEP}px`);
    expect(stored("rz5")?.ip).toBe(140 + BIG_STEP);
    // The keys stop at the handle: the grid's cell focus did not move.
    expect(table().getAttribute("aria-activedescendant")).toBeNull();
    for (let i = 0; i < 10; i++) fireEvent.keyDown(h, { key: "ArrowLeft", shiftKey: true });
    expect(colWidths()[0]).toBe(`${MIN_WIDTH}px`);
    fireEvent.keyDown(h, { key: "Enter" });
    expect(document.activeElement).toBe(table());
    h.focus();
    fireEvent.keyDown(h, { key: "Escape" });
    expect(document.activeElement).toBe(table());
  });

  it("mirrors the arrow keys right to left", () => {
    grid("rz6", { dir: "rtl" });
    const h = handle("Address");
    fireEvent.keyDown(h, { key: "ArrowLeft" });
    expect(colWidths()[0]).toBe(`${140 + STEP}px`);
  });

  it("fits a column to its content on a double click and on a double tap", () => {
    measureText();
    grid("rz7");
    fireEvent.dblClick(handle("Name"));
    // The longest name, 39 characters at 7 px, and one pixel against rounding.
    expect(colWidths()[1]).toBe(`${39 * 7 + 1}px`);
    tap(handle("Address"));
    tap(handle("Address"));
    expect(colWidths()[0]).toBe(`${"192.0.2.200".length * 7 + 1}px`);
    expect(stored("rz7")).toEqual({ ip: 78, name: 274 });
  });

  it("restores the widths after a reload and drops them with the footer's reset", () => {
    writeWidths(widthsKey("rz8", undefined), { ip: 250, name: 120 });
    const first = grid("rz8");
    expect(colWidths()).toEqual(["250px", "120px", ""]);
    first.unmount();
    grid("rz8");
    expect(colWidths()).toEqual(["250px", "120px", ""]);
    fireEvent.click(screen.getByTestId("grid-reset-widths"));
    expect(colWidths()).toEqual(["140px", "", "90px"]);
    expect(stored("rz8")).toBeNull();
    expect(screen.queryByTestId("grid-reset-widths")).toBeNull();
    expect(table().style.width).toBe("");
  });

  it("resets the widths from the column menu of the filter bar instead of the footer", () => {
    writeWidths(widthsKey("rz9", undefined), { ip: 250 });
    render(() => {
      const state = createColumnState("rz9", () => columns);
      return (
        <>
          <FilterBar label="Filter" placeholder="Filter" value="" onInput={() => {}} columns={state} />
          <DataGrid id="rz9" label="Addresses" columns={columns} rows={ROWS} rowId={(r) => r.id} columnState={state} />
        </>
      );
    });
    expect(colWidths()[0]).toBe("250px");
    expect(screen.queryByTestId("grid-reset-widths")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Choose columns" }));
    fireEvent.click(screen.getByTestId("reset-column-widths"));
    expect(colWidths()[0]).toBe("140px");
    expect(stored("rz9")).toBeNull();
    expect((screen.getByTestId("reset-column-widths") as HTMLButtonElement).disabled).toBe(true);
  });

  it("ignores stored widths and offers no handles on a narrow screen", () => {
    writeWidths(widthsKey("rz10", undefined), { ip: 250 });
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: query === NARROW_QUERY,
      addEventListener() {},
      removeEventListener() {},
    }));
    grid("rz10");
    expect(colWidths()).toEqual(["140px", "", "90px"]);
    expect(within(table()).queryAllByRole("separator")).toHaveLength(0);
    expect(screen.queryByTestId("grid-reset-widths")).toBeNull();
  });
});
