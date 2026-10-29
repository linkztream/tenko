// The data grid with group rows (design/README.md, "Group row"). A group collapses a run of
// similar rows into one 28 px row: a chevron, the label, the count and, when every row of the
// group shares it, the sentence that would otherwise repeat on every row. The views of
// Discovery and Reconciliation (U4), Jobs by day (U5) and the IPAM networks (U6) use it.
//
// Use it like DataGrid, with `groups` instead of `rows`:
//
//   <GroupedGrid id="findings" label="Findings" columns={columns} rowId={(f) => f.id}
//     groups={[{ key: "act", label: <b>Act now</b>, text: "Act now", count: 1, rows: act },
//              { key: "info", label: <b>Info</b>, text: "Info", count: 23, rows: info,
//                collapsed: info.length > 10, sentence: "Intent wins: ..." }]} />
//
// - Every other prop is the DataGrid prop of the same name, typed by the row: the grid calls it
//   for the rows of the groups only, never for a group row or a tail.
// - The open or closed state is kept per grid id and group key for the session (groups.ts); a
//   group the person has not touched follows its `collapsed` default.
// - Keyboard: a group row is a row of the grid. Enter and Space open and close it, a click on it
//   does too; its button carries aria-expanded and the row `data-expanded`. Group rows cannot be
//   selected.
// - Virtualization stays: the group rows, the rows of open groups and the tails are one list of
//   equal rows for the grid's window.
// - The majority rule of the columns (`Column.majority`) reads every row of every group, the
//   rows of closed groups included, so opening a group never changes a header.
// - The footer counts the rows of the groups, not the group rows.
import { createMemo, Show, untrack, type JSX } from "solid-js";
import { Icon } from "../components/Icon";
import { formatNumber, t } from "../i18n";
import { createGridSelection, DataGrid, type CellEditor, type DataGridProps } from "./DataGrid";
import { createGroupState, flattenGroups, type GroupedItem, type RowGroup } from "./groups";
import type { ColumnState } from "./prefs";
import type { Column, RowAction } from "./types";
import "./group.css";

export type { GroupedItem, RowGroup } from "./groups";

export interface GroupedGridProps<T> extends Omit<DataGridProps<T>, "rows" | "expanded" | "onToggle" | "majorityRows"> {
  groups: readonly RowGroup<T>[];
}

/** The id of a group row or a tail; never the id of a data row. */
const lineId = (type: "group" | "tail", key: string) => `\u0001${type}:${key}`;

/** The group row: chevron, label, count, what the group means and its shared sentence. */
export function GroupRowCell<T>(props: { group: RowGroup<T>; open: boolean; onToggle: () => void }) {
  const count = () => `${formatNumber(props.group.count)}${props.group.more ? "+" : ""}`;
  return (
    <span class="group-cell" data-testid="group-row" data-group={props.group.key} data-open={props.open ? "true" : "false"}>
      <button
        type="button"
        class="group-toggle"
        tabIndex={-1}
        aria-expanded={props.open}
        aria-label={t(props.open ? "grid.group.collapse" : "grid.group.expand", { group: props.group.text, count: count() })}
        onClick={() => props.onToggle()}
      >
        <Icon name={props.open ? "chev-d" : "chev-r"} size="xs" />
        <span class="group-label">{props.group.label}</span>{" "}
        <span class="group-count" data-testid="group-count">
          {count()}
        </span>
      </button>
      <Show when={props.group.note}>
        <span class="group-note" data-testid="group-note">
          {props.group.note}
        </span>
      </Show>
      <Show when={props.group.sentence}>
        <span class="group-sentence" data-testid="group-sentence" title={props.group.sentence}>
          {props.group.sentence}
        </span>
      </Show>
    </span>
  );
}

export function GroupedGrid<T>(props: GroupedGridProps<T>) {
  const state = untrack(() => createGroupState(props.id));
  const isOpen = (group: RowGroup<T>) => state.isOpen(group.key, group.collapsed);
  const toggle = (group: RowGroup<T>) => state.toggle(group.key, group.collapsed);

  // One item per row object, so a row keeps its DOM row while groups open and close.
  const rowItems = new WeakMap<object, GroupedItem<T>>();
  const rowItem = (row: T): GroupedItem<T> => {
    const key = row as unknown as object;
    let item = rowItems.get(key);
    if (!item) {
      item = { type: "row", key: props.rowId(row), row };
      rowItems.set(key, item);
    }
    return item;
  };
  const items = createMemo(() => flattenGroups(props.groups, isOpen, rowItem));
  const allRows = createMemo(() => props.groups.flatMap((g) => g.rows));
  const allItems = createMemo(() => allRows().map(rowItem));

  // Columns, lifted to items once per column object, so the grid keeps its cells.
  const lifted = new WeakMap<Column<T>, Column<GroupedItem<T>>>();
  const lift = (c: Column<T>): Column<GroupedItem<T>> => {
    let out = lifted.get(c);
    if (!out) {
      const majority = c.majority;
      const text = c.text;
      const editable = c.editable;
      out = {
        ...c,
        render: (item) => (item.type === "row" ? c.render(item.row) : null),
        text: text ? (item) => (item.type === "row" ? text(item.row) : item.group.text) : undefined,
        editable: (item) => item.type === "row" && (editable?.(item.row) ?? true),
        majority: majority ? (item) => (item.type === "row" ? majority(item.row) : undefined) : undefined,
      };
      lifted.set(c, out);
    }
    return out;
  };
  const columns = createMemo(() => props.columns.map(lift));
  const columnState = untrack((): ColumnState<GroupedItem<T>> | undefined => {
    const own = props.columnState;
    if (!own) return undefined;
    return { ...own, all: () => own.all().map(lift), visible: () => own.visible().map(lift) };
  });
  const selection = untrack(() => props.selection ?? createGridSelection(allRows, (r) => props.rowId(r), (r) => !props.noSelection && (props.selectable?.(r) ?? true)));

  const on = <R,>(fn: ((row: T) => R) | undefined) => (fn ? (item: GroupedItem<T>) => (item.type === "row" ? fn(item.row) : undefined) : undefined);
  const editors = () => {
    const own = props.editors;
    if (!own) return undefined;
    const out: Record<string, CellEditor<GroupedItem<T>>> = {};
    for (const [id, editor] of Object.entries(own)) {
      out[id] = (p) => (p.row.type === "row" ? editor({ row: p.row.row, close: p.close }) : null);
    }
    return out;
  };
  const rowActions = (): RowAction<GroupedItem<T>>[] | undefined =>
    props.rowActions?.map((a) => ({
      id: a.id,
      label: a.label,
      danger: a.danger,
      run: (item) => {
        if (item.type === "row") a.run(item.row);
      },
      disabled: (item) => item.type !== "row" || (a.disabled?.(item.row) ?? false),
      hidden: (item) => item.type !== "row" || (a.hidden?.(item.row) ?? false),
    }));
  const dataRows = () => allRows().length;

  return (
    <DataGrid<GroupedItem<T>>
      id={props.id}
      label={props.label}
      columns={columns()}
      columnState={columnState}
      rows={items()}
      rowId={(item) => (item.type === "row" ? props.rowId(item.row) : lineId(item.type, item.key))}
      rowLabel={props.rowLabel ? (item) => (item.type === "row" ? props.rowLabel!(item.row) : item.group.text) : undefined}
      rowKey={(item) => (item.type === "row" ? props.rowKey?.(item.row) : `${item.type}:${item.key}`)}
      selectable={(item) => item.type === "row" && !props.noSelection && (props.selectable?.(item.row) ?? true)}
      fullRow={(item): JSX.Element | null => {
        if (item.type === "group") return <GroupRowCell group={item.group} open={item.open} onToggle={() => toggle(item.group)} />;
        if (item.type === "tail") return item.group.tail?.() ?? null;
        return props.fullRow?.(item.row) ?? null;
      }}
      rowClass={(item) => {
        if (item.type === "group") return ["group-row", item.group.tone].filter(Boolean).join(" ");
        if (item.type === "tail") return "group-tail";
        return props.rowClass?.(item.row);
      }}
      expanded={(item) => (item.type === "group" ? item.open : undefined)}
      onToggle={(item) => {
        if (item.type === "group") toggle(item.group);
      }}
      majorityRows={allItems()}
      selection={selection}
      noSelection={props.noSelection}
      sort={props.sort}
      onSort={props.onSort}
      loading={props.loading}
      initial={props.initial}
      hasMore={props.hasMore}
      onLoadMore={props.onLoadMore}
      error={props.error}
      onRetry={props.onRetry}
      empty={props.empty}
      onOpen={on(props.onOpen)}
      onDetails={on(props.onDetails)}
      onOpenPage={on(props.onOpenPage)}
      editors={editors()}
      rowActions={rowActions()}
      flashed={props.flashed}
      dragItems={props.dragItems ? (list) => props.dragItems!(list.flatMap((item) => (item.type === "row" ? [item.row] : []))) : undefined}
      draggable={(item) => item.type === "row" && (props.draggable?.(item.row) ?? true)}
      dragLabel={props.dragLabel}
      statusBar={props.statusBar}
      footer={props.footer}
      count={props.count ?? { value: dataRows(), noun: t("grid.rows", { count: dataRows() }) }}
      ref={props.ref}
    />
  );
}
