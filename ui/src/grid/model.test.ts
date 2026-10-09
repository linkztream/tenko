import { createRoot } from "solid-js";
import { describe, expect, it } from "vitest";
import { moveFocus, scrollToShow, visibleWindow } from "./focus";
import { orderColumns } from "./prefs";
import { formatTerms, parseQuery, tokenize, type QueryField } from "./query";
import { createSelection, idsBetween } from "./selection";
import { nextSort, sortParam, type Column } from "./types";

describe("focus", () => {
  const bounds = { rows: 10, cols: 4, page: 3 };

  it("moves by row and column within the bounds, the header being row -1", () => {
    expect(moveFocus({ row: 0, col: 1 }, "ArrowDown", bounds)).toEqual({ row: 1, col: 1 });
    expect(moveFocus({ row: 0, col: 1 }, "k", bounds)).toEqual({ row: -1, col: 1 });
    expect(moveFocus({ row: -1, col: 1 }, "ArrowUp", bounds)).toEqual({ row: -1, col: 1 });
    expect(moveFocus({ row: 9, col: 1 }, "j", bounds)).toEqual({ row: 9, col: 1 });
    expect(moveFocus({ row: 2, col: 3 }, "ArrowRight", bounds)).toEqual({ row: 2, col: 3 });
    expect(moveFocus({ row: 2, col: 0 }, "ArrowLeft", bounds)).toEqual({ row: 2, col: 0 });
  });

  it("jumps with Home, End, Ctrl and the page keys", () => {
    expect(moveFocus({ row: 5, col: 2 }, "Home", bounds)).toEqual({ row: 5, col: 0 });
    expect(moveFocus({ row: 5, col: 2 }, "End", bounds)).toEqual({ row: 5, col: 3 });
    expect(moveFocus({ row: 5, col: 2 }, "Home", bounds, true)).toEqual({ row: 0, col: 2 });
    expect(moveFocus({ row: 5, col: 2 }, "End", bounds, true)).toEqual({ row: 9, col: 2 });
    expect(moveFocus({ row: 5, col: 2 }, "PageDown", bounds)).toEqual({ row: 8, col: 2 });
    expect(moveFocus({ row: 8, col: 2 }, "PageDown", bounds)).toEqual({ row: 9, col: 2 });
    expect(moveFocus({ row: 1, col: 2 }, "PageUp", bounds)).toEqual({ row: 0, col: 2 });
  });

  it("renders only a window of rows around the viewport", () => {
    expect(visibleWindow(0, 280, 28, 65_536, 10)).toEqual({ start: 0, end: 20 });
    expect(visibleWindow(28 * 1000, 280, 28, 65_536, 10)).toEqual({ start: 990, end: 1020 });
    expect(visibleWindow(28 * 65_530, 280, 28, 65_536, 10)).toEqual({ start: 65_520, end: 65_536 });
    expect(visibleWindow(0, 280, 28, 0)).toEqual({ start: 0, end: 0 });
  });

  it("scrolls only as far as needed to show a row", () => {
    expect(scrollToShow(5, 0, 280, 28)).toBe(0);
    expect(scrollToShow(12, 0, 280, 28)).toBe(13 * 28 - 280);
    expect(scrollToShow(2, 280, 280, 28)).toBe(56);
  });
});

describe("selection", () => {
  it("lists the ids between two rows in either direction", () => {
    expect(idsBetween(["a", "b", "c", "d"], "b", "d")).toEqual(["b", "c", "d"]);
    expect(idsBetween(["a", "b", "c", "d"], "c", "a")).toEqual(["a", "b", "c"]);
    expect(idsBetween(["a", "b"], "x", "b")).toEqual(["b"]);
  });

  it("toggles, extends from the anchor, selects all and drops rows that leave the list", () => {
    createRoot((dispose) => {
      let ids = ["a", "b", "c", "d", "e"];
      const [list, setList] = [() => ids, (next: string[]) => (ids = next)];
      const sel = createSelection(list);
      sel.toggle("b");
      sel.extendTo("d");
      expect(sel.ids()).toEqual(["b", "c", "d"]);
      sel.toggle("c");
      expect(sel.ids()).toEqual(["b", "d"]);
      sel.toggle("x");
      expect(sel.count()).toBe(2);
      sel.selectAll();
      expect(sel.all()).toBe(true);
      sel.clear();
      expect(sel.count()).toBe(0);
      sel.set(["a", "zz"]);
      expect(sel.ids()).toEqual(["a"]);
      setList(["b", "c"]);
      dispose();
    });
  });
});

describe("filter query", () => {
  const fields: QueryField[] = [
    { name: "mode", values: ["static", "reserved", "dynamic", "unmanaged"] },
    { name: "status", multi: true },
    { name: "tag" },
  ];

  it("keeps quoted values together", () => {
    expect(tokenize('tag:"lab rack" nas')).toEqual(["tag:lab rack", "nas"]);
  });

  it("turns known field terms into parameters and the rest into q", () => {
    expect(parseQuery("mode:reserved cam 192.0.2", fields)).toEqual({
      params: { mode: "reserved", q: "cam 192.0.2" },
      text: "cam 192.0.2",
      invalid: [],
    });
  });

  it("leaves IPv6 addresses and MACs alone because their prefix is not a field", () => {
    const parsed = parseQuery("2001:db8::10 00:00:5e:00:53:01", fields);
    expect(parsed.params).toEqual({ q: "2001:db8::10 00:00:5e:00:53:01" });
  });

  it("joins repeated multi-value fields and reports values a field does not allow", () => {
    const parsed = parseQuery("status:active status:planned mode:sometimes", fields);
    expect(parsed.params).toEqual({ status: "active,planned" });
    expect(parsed.invalid).toEqual([{ field: "mode", value: "sometimes" }]);
  });

  it("writes parameters back as terms", () => {
    expect(formatTerms({ mode: "reserved", tag: "lab rack", q: "x", status: undefined })).toBe('mode:reserved tag:"lab rack"');
  });
});

describe("sort and columns", () => {
  it("cycles a column through ascending, descending and off", () => {
    expect(nextSort(null, "name")).toEqual({ field: "name", desc: false });
    expect(nextSort({ field: "name", desc: false }, "name")).toEqual({ field: "name", desc: true });
    expect(nextSort({ field: "name", desc: true }, "name")).toBeNull();
    expect(nextSort({ field: "name", desc: true }, "mode")).toEqual({ field: "mode", desc: false });
    expect(sortParam({ field: "name", desc: true })).toBe("-name");
    expect(sortParam(null)).toBeUndefined();
  });

  it("orders columns by the stored order and keeps unknown columns in place", () => {
    const col = (id: string): Column<unknown> => ({ id, header: () => id, render: () => null });
    const cols = [col("a"), col("b"), col("c"), col("new")];
    expect(orderColumns(cols, ["c", "a", "b"]).map((c) => c.id)).toEqual(["c", "a", "b", "new"]);
    expect(orderColumns(cols, []).map((c) => c.id)).toEqual(["a", "b", "c", "new"]);
  });
});
