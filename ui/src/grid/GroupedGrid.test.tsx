// The group rows of the data grid and the majority in the header: groups in their order with
// their counts and the sentence said once, a group closed by default and opened with Enter, Space
// or a click (kept for the session), the rows of open groups only, no selection of a group row,
// a header that speaks for a column whose rows all agree, and virtualization with groups.
import { fireEvent, render, screen, within } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { DataGrid } from "./DataGrid";
import { GroupedGrid, type RowGroup } from "./GroupedGrid";
import { createGroupState, flattenGroups, resetGroupStateForTest, sharedValue } from "./groups";
import { columnMajorities } from "./majority";
import type { Column } from "./types";

interface Row {
  id: string;
  ip: string;
  state: string;
  rule?: string;
}

const columns: Column<Row>[] = [
  { id: "ip", header: () => "Address", width: 140, render: (r) => r.ip, text: (r) => r.ip },
  { id: "state", header: () => "State", render: (r) => <span class="badge">{r.state}</span>, text: (r) => r.state, majority: (r) => r.state },
];

function ghosts(n: number, from = 10): Row[] {
  return Array.from({ length: n }, (_, i) => ({ id: `g${i}`, ip: `192.0.2.${from + i}`, state: "Intent wins", rule: "Intent wins: the host is managed." }));
}

const conflict: Row = { id: "c1", ip: "192.0.2.5", state: "No winner" };

function groupsOf(info: Row[], act: Row[] = [conflict]): RowGroup<Row>[] {
  return [
    { key: "act", label: <b>Act now</b>, text: "Act now", count: act.length, rows: act },
    {
      key: "info",
      label: <b>Info</b>,
      text: "Info",
      count: info.length,
      rows: info,
      collapsed: info.length > 10,
      note: "Not seen for longer than the lease.",
      sentence: sharedValue(info, (r) => r.rule),
    },
  ];
}

const grid = () => screen.getByRole("grid", { name: "Findings" });
const lines = () => within(grid()).getAllByTestId("row");
const groupRows = () => lines().filter((r) => r.dataset.expanded !== undefined);
const dataRows = () => lines().filter((r) => r.dataset.expanded === undefined);
const key = (k: string) => fireEvent.keyDown(grid(), { key: k });

afterEach(() => resetGroupStateForTest());

describe("the group model", () => {
  it("lists each group that holds rows, then its rows while it is open", () => {
    const state = createGroupState("model");
    const items = flattenGroups(groupsOf(ghosts(3)), (g) => state.isOpen(g.key, g.collapsed), (row) => ({ type: "row", key: row.id, row }));
    expect(items.map((i) => (i.type === "row" ? i.row.id : `${i.type}:${i.key}`))).toEqual(["group:act", "c1", "group:info", "g0", "g1", "g2"]);
    const empty = flattenGroups(groupsOf([], []), () => true, (row) => ({ type: "row", key: row.id, row }));
    expect(empty).toEqual([]);
  });

  it("says a value once only when every row has the same one", () => {
    expect(sharedValue(ghosts(23), (r) => r.rule)).toBe("Intent wins: the host is managed.");
    expect(sharedValue([...ghosts(2), conflict], (r) => r.rule)).toBeUndefined();
    expect(sharedValue([], (r: Row) => r.rule)).toBeUndefined();
  });

  it("keeps a choice per grid and key, and follows the default until one is made", () => {
    const a = createGroupState("keep");
    expect(a.isOpen("info", true)).toBe(false);
    a.toggle("info", true);
    expect(a.isOpen("info", true)).toBe(true);
    // A second grid of the same id in this session starts from the choice.
    expect(createGroupState("keep").isOpen("info", true)).toBe(true);
    expect(createGroupState("other").isOpen("info", true)).toBe(false);
  });
});

describe("the majority in the header", () => {
  it("names the value every row shares and nothing when one differs or is missing", () => {
    expect(columnMajorities(columns, ghosts(3)).get("state")).toBe("Intent wins");
    expect(columnMajorities(columns, [...ghosts(3), conflict]).has("state")).toBe(false);
    expect(columnMajorities(columns, ghosts(1)).has("state")).toBe(false);
    expect(columnMajorities(columns, [...ghosts(2), { id: "x", ip: "192.0.2.99", state: "" }]).has("state")).toBe(false);
    expect(columnMajorities(columns, ghosts(3)).has("ip")).toBe(false);
  });

  it("says the shared value once in the header and leaves the cells empty, until a row differs", () => {
    const [list, setList] = createSignal(ghosts(4));
    render(() => <DataGrid id="maj" label="Findings" columns={columns} rows={list()} rowId={(r) => r.id} noSelection />);
    const header = () => within(grid()).getAllByRole("columnheader").find((h) => h.dataset.col === "state");
    expect(header()?.textContent).toBe("State · Intent wins");
    expect(lines().every((r) => r.querySelector("[data-col='state']")?.textContent === "")).toBe(true);
    setList([...ghosts(4), conflict]);
    expect(header()?.textContent).toBe("State");
    expect(lines().map((r) => r.querySelector("[data-col='state']")?.textContent)).toContain("No winner");
  });
});

describe("GroupedGrid", () => {
  it("draws 23 identical rows as one closed group that says the shared sentence once, after the group to act on", async () => {
    render(() => <GroupedGrid id="g1" label="Findings" columns={columns} groups={groupsOf(ghosts(23))} rowId={(r) => r.id} noSelection />);
    expect(groupRows().map((r) => r.dataset.key)).toEqual(["group:act", "group:info"]);
    const info = groupRows()[1] as HTMLElement;
    expect(info.dataset.expanded).toBe("false");
    expect(within(info).getByRole("button").getAttribute("aria-expanded")).toBe("false");
    expect(within(info).getByTestId("group-count").textContent).toBe("23");
    expect(within(info).getByTestId("group-sentence").textContent).toBe("Intent wins: the host is managed.");
    expect(screen.getAllByText("Intent wins: the host is managed.")).toHaveLength(1);
    // Only the conflict is listed; the footer counts the rows of the groups.
    expect(dataRows().map((r) => r.dataset.id)).toEqual(["c1"]);
    expect(screen.getByTestId("grid-foot").textContent).toContain("24 rows");
    expect(await axeViolations(screen.getByTestId("grid-g1"))).toEqual([]);
  });

  it("opens and closes a group with Enter, Space and a click, and keeps the choice for the session", () => {
    const view = render(() => <GroupedGrid id="g2" label="Findings" columns={columns} groups={groupsOf(ghosts(12))} rowId={(r) => r.id} noSelection />);
    fireEvent.focus(grid());
    key("ArrowDown");
    key("ArrowDown");
    // The focus is on the Info group row: Enter opens it.
    key("Enter");
    expect(groupRows()[1]?.dataset.expanded).toBe("true");
    expect(dataRows()).toHaveLength(13);
    key(" ");
    expect(dataRows()).toHaveLength(1);
    fireEvent.click(within(groupRows()[1] as HTMLElement).getByRole("button"));
    expect(dataRows()).toHaveLength(13);
    view.unmount();
    render(() => <GroupedGrid id="g2" label="Findings" columns={columns} groups={groupsOf(ghosts(12))} rowId={(r) => r.id} noSelection />);
    expect(groupRows()[1]?.dataset.expanded).toBe("true");
  });

  it("labels the toggle with the group and its count", () => {
    render(() => <GroupedGrid id="g3" label="Findings" columns={columns} groups={groupsOf(ghosts(12))} rowId={(r) => r.id} noSelection />);
    expect(screen.getByRole("button", { name: "Open Info: 12" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close Act now: 1" })).toBeTruthy();
  });

  it("selects rows and never a group row, and opens a row but not a group", () => {
    const open = vi.fn();
    render(() => <GroupedGrid id="g4" label="Findings" columns={columns} groups={groupsOf(ghosts(3))} rowId={(r) => r.id} onOpen={open} />);
    const checks = within(grid()).queryAllByRole("checkbox", { name: /^Select 192/ });
    expect(checks).toHaveLength(4);
    expect(groupRows().every((r) => r.getAttribute("aria-selected") === null)).toBe(true);
    fireEvent.focus(grid());
    key("ArrowDown");
    key("Enter");
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ id: "c1" }));
    fireEvent.dblClick(groupRows()[0]?.querySelector("td.full") as HTMLElement);
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("speaks for a column across every group, the closed ones included", () => {
    render(() => <GroupedGrid id="g5" label="Findings" columns={columns} groups={groupsOf(ghosts(12), [])} rowId={(r) => r.id} noSelection />);
    const header = within(grid()).getAllByRole("columnheader").find((h) => h.dataset.col === "state");
    expect(header?.textContent).toBe("State · Intent wins");
  });

  it("keeps rows of 28 px and draws only the rows in view of a long open group", () => {
    const many = ghosts(400).map((r, i) => ({ ...r, ip: `198.51.100.${i % 256}`, state: i % 2 ? "Intent wins" : "Lease wins" }));
    const groups: RowGroup<Row>[] = [{ key: "all", label: <b>Review</b>, text: "Review", count: many.length, rows: many }];
    render(() => <GroupedGrid id="g6" label="Findings" columns={columns} groups={groups} rowId={(r) => r.id} noSelection />);
    // The fallback viewport of 640 px holds about 22 rows of 28 px plus the overscan.
    expect(lines().length).toBeGreaterThan(10);
    expect(lines().length).toBeLessThan(60);
    const spacer = grid().querySelector("tr.spacer td") as HTMLElement | null;
    expect(spacer?.style.height).toBe(`${(401 - lines().length) * 28}px`);
  });
});
