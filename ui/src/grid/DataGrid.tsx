// The data grid of every list view (API-08): keyboard first, virtualized, 28 px rows by
// default (the density preference sets 24 or 34), identifiers in the data font.
//
// - Focus is a cell, not a row (design/README.md): arrow keys or J and K move it, Home and End
//   go to the first and last column (with Ctrl to the first and last row), Page Up and Page
//   Down move a screen. The table keeps the DOM focus and points at the cell with
//   aria-activedescendant, so a list of a thousand rows is one tab stop.
// - Selection is separate from focus: Space toggles the focused row, Shift with an arrow or a
//   click extends from the anchor, Ctrl+click toggles, Ctrl+A selects every loaded row, Esc
//   clears it. Rows that cannot be selected (free gaps, group rows) are skipped.
// - Enter edits the focused cell when its column can edit the row, else opens the row; "."
//   opens the details panel and Shift+Enter the full page. The context-menu key or Shift+F10
//   opens the row's actions. Other keys bubble up to the view (M, L, N, ...).
// - Sorting and filtering happen on the server: a header click (or Enter on the header row)
//   asks the view for the next sort.
// - Only the rows in view (plus an overscan) are in the DOM; spacer rows keep the scroll
//   height. More pages load as the end comes into view.
// - Loading never flashes: the loading row appears only after 300 ms, and a reload keeps the
//   rows it replaces until the new ones arrive.
// - Columns are resized on the handle at the trailing edge of their header (ColumnResize.tsx):
//   drag, double-click to fit, or Tab from the grid to the handle of the focused column and
//   the arrow keys. The widths are kept per list and user (widths.ts); the column menu of the
//   filter bar resets them, or the footer when the list has no column menu.
// - A row that opens and closes (a group row, see GroupedGrid.tsx) says so on its button with
//   aria-expanded; Enter, Space and a click toggle it instead of opening or selecting.
// - A column with a majority rule says the value every row shares once in its header and leaves
//   its cells empty (majority.ts).
import {
  createEffect,
  createMemo,
  createSignal,
  For,
  Match,
  on,
  onCleanup,
  onMount,
  Show,
  Switch,
  untrack,
  type JSX,
} from "solid-js";
import { density } from "../app/prefs";
import { ErrorNotice } from "../components/Notice";
import { Icon } from "../components/Icon";
import { Si } from "../components/Si";
import { t } from "../i18n";
import { setSelectionStatus } from "../shell/status";
import { isTyping } from "../shell/keyboard";
import { ColumnResize, createResizer } from "./ColumnResize";
import { DRAG_MIME, endDrag, startDrag, type DragItem } from "./dnd";
import { isMoveKey, logicalArrow, moveFocus, ROW_HEIGHT, scrollToShow, visibleWindow, type CellFocus } from "./focus";
import { columnMajorities } from "./majority";
import { Menu } from "./Menu";
import { createColumnState, type ColumnState } from "./prefs";
import { createSelection, type Selection } from "./selection";
import { delayed } from "./source";
import type { Column, RowAction, SortState } from "./types";
import { nextSort } from "./types";
import "./grid.css";

/** Height of the sticky header row in pixels (design.css, `.grid thead th`). */
const HEADER_HEIGHT = 30;
/** Viewport assumed before layout is known (and under test, where jsdom has none). */
const FALLBACK_VIEWPORT = 640;
/** Rows before the end of the loaded rows at which the next page is requested. */
const LOAD_AHEAD = 20;
/** Widths of the selection and actions columns (grid.css, `col.c-check` and `col.c-acts`). */
const CHECK_WIDTH = 34;
const ACTIONS_WIDTH = 40;

export interface EditorProps<T> {
  row: T;
  /** Ends editing; the grid takes the focus back. */
  close: () => void;
}

/** An inline editor for a column (Enter or double-click on an editable cell). */
export type CellEditor<T> = (props: EditorProps<T>) => JSX.Element;

export interface DataGridProps<T> {
  /** Grid id: the column preference key, `data-testid="grid-<id>"` and the DOM id prefix. */
  id: string;
  /** Accessible name of the grid. */
  label: string;
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowId: (row: T) => string;
  /** A short name of the row for labels ("Select 192.0.2.41"); the first column's text by default. */
  rowLabel?: (row: T) => string;
  /** `data-key` of a row: a human key such as an address or a name, for tests and links. */
  rowKey?: (row: T) => string | undefined;
  /** Rows that can be selected (default: all). */
  selectable?: (row: T) => boolean;
  /** A row drawn as one wide cell instead of columns (a free gap, a group row), or null. */
  fullRow?: (row: T) => JSX.Element | null;
  /**
   * Whether a row that opens and closes (a group row) is open; undefined for every other row.
   * Such a row carries `data-expanded` (its button inside carries aria-expanded, which a row of a
   * grid may not), and Enter, Space and a click call `onToggle` for it.
   */
  expanded?: (row: T) => boolean | undefined;
  onToggle?: (row: T) => void;
  /**
   * The rows the majority rule of the columns reads (`Column.majority`); the listed rows by
   * default. A grid with group rows or free gaps passes its data rows, the collapsed ones included.
   */
  majorityRows?: readonly T[];
  rowClass?: (row: T) => string | undefined;
  /** The selection (create it with createGridSelection to share it with an action bar). */
  selection?: Selection;
  /** Without a selection column (lists that offer no bulk action). */
  noSelection?: boolean;
  columnState?: ColumnState<T>;
  sort?: SortState | null;
  onSort?: (sort: SortState | null) => void;
  /** A request is in flight. */
  loading?: boolean;
  /** The first page has not arrived yet. */
  initial?: boolean;
  hasMore?: boolean;
  onLoadMore?: () => void;
  error?: unknown;
  onRetry?: () => void;
  /** Shown instead of rows when the list is empty. */
  empty?: JSX.Element;
  onOpen?: (row: T) => void;
  onDetails?: (row: T) => void;
  onOpenPage?: (row: T) => void;
  /** Inline editors by column id. */
  editors?: Readonly<Record<string, CellEditor<T>>>;
  rowActions?: readonly RowAction<T>[];
  flashed?: (id: string) => boolean;
  /** Enables dragging rows: the objects a drag of these rows carries, or null to refuse. */
  dragItems?: (rows: T[]) => DragItem[] | null;
  /** Whether a row may be dragged at all (default: every selectable row when `dragItems` is set). */
  draggable?: (row: T) => boolean;
  /** The text of the drag ghost ("Moving 3 hosts"). */
  dragLabel?: (items: readonly DragItem[]) => string;
  /** Reports the selection count to the status bar (default true). */
  statusBar?: boolean;
  /** Extra content of the footer line, after the row count. */
  footer?: JSX.Element;
  /**
   * What the footer counts instead of the rows, for a list whose rows are not all objects
   * (an address list with its free gaps): the number, the noun after it, and a tooltip that
   * says what is counted.
   */
  count?: { value: number; noun: string; title?: string | undefined } | undefined;
  /** Called with the table element, for views that move the focus into the grid (the `]` key). */
  ref?: (el: HTMLTableElement) => void;
}

/** The value every row of a column shares, after its header text ("State · all insecure"). */
function Majority(props: { value: string | undefined }) {
  return (
    <Show when={props.value}>
      {(value) => (
        <span class="th-majority" data-testid="th-majority">
          {" "}
          {t("grid.majority", { value: value() })}
        </span>
      )}
    </Show>
  );
}

/** A selection over the selectable rows of a list. */
export function createGridSelection<T>(
  rows: () => readonly T[],
  rowId: (row: T) => string,
  selectable: (row: T) => boolean = () => true,
): Selection {
  return createSelection(createMemo(() => rows().filter(selectable).map(rowId)));
}

export function DataGrid<T>(props: DataGridProps<T>) {
  let wrap!: HTMLDivElement;
  let table!: HTMLTableElement;

  // The column state and the selection are fixed for the life of the grid.
  const columnState = untrack(() => props.columnState ?? createColumnState(props.id, () => props.columns));
  const selectableRow = (row: T) => !props.noSelection && (props.selectable?.(row) ?? true);
  const selection = untrack(
    () => props.selection ?? createGridSelection(() => props.rows, (r) => props.rowId(r), selectableRow),
  );
  const hasCheck = () => !props.noSelection;
  const hasActions = () => (props.rowActions?.length ?? 0) > 0;
  const cols = () => columnState.visible();
  /** Focusable columns: the selection column, the data columns, the actions column. */
  const colCount = () => (hasCheck() ? 1 : 0) + cols().length + (hasActions() ? 1 : 0);
  const span = () => colCount();
  const widths = columnState.widths;
  const resizer = createResizer({
    widths,
    columns: cols,
    table: () => table,
    extra: () => (hasCheck() ? CHECK_WIDTH : 0) + (hasActions() ? ACTIONS_WIDTH : 0),
  });

  const rowHeight = () => ROW_HEIGHT[density()];
  const [scrollTop, setScrollTop] = createSignal(0);
  const [viewport, setViewport] = createSignal(FALLBACK_VIEWPORT);
  const [focus, setFocus] = createSignal<CellFocus>({ row: 0, col: hasCheck() ? 1 : 0 });
  const [focusedId, setFocusedId] = createSignal<string | null>(null);
  const [active, setActive] = createSignal(false);
  const [editing, setEditing] = createSignal<{ id: string; col: string } | null>(null);
  const [menu, setMenu] = createSignal<{ row: T; anchor: HTMLElement } | null>(null);
  // eslint-disable-next-line solid/reactivity -- delayed() reads it inside an effect
  const slowLoading = delayed(() => !!props.loading);

  const ids = createMemo(() => props.rows.map((r) => props.rowId(r)));
  /** The value a column says once in its header, by column id (majority.ts). */
  const majorities = createMemo(() => {
    const columns = cols();
    if (!columns.some((c) => c.majority)) return new Map<string, string>();
    return columnMajorities(columns, props.majorityRows ?? props.rows);
  });
  const isToggle = (row: T | undefined): row is T => row !== undefined && props.expanded?.(row) !== undefined;
  const index = createMemo(() => new Map(ids().map((id, i) => [id, i])));

  const window = createMemo(() =>
    visibleWindow(
      scrollTop(),
      Math.max(0, viewport() - HEADER_HEIGHT),
      rowHeight(),
      props.rows.length,
      10,
    ),
  );
  const windowRows = createMemo(() => {
    const { start, end } = window();
    return props.rows.slice(start, end).map((row, k) => ({ row, index: start + k }));
  });

  /** The person moved the focus to the header row (it stays there when rows change). */
  let headerChosen = false;

  // Keep the focus on the same row when the rows change underneath it.
  createEffect(
    on(ids, (list) => {
      const id = focusedId();
      const f = focus();
      if (id !== null) {
        const i = index().get(id);
        if (i !== undefined) {
          if (i !== f.row) setFocus({ ...f, row: i });
          return;
        }
      }
      if (f.row >= list.length) setFocus({ ...f, row: Math.max(-1, list.length - 1) });
      // The header got the focus only because the list was empty: the first row takes it back.
      else if (f.row < 0 && !headerChosen && list.length > 0) setFocus({ ...f, row: 0 });
    }),
  );

  // Load the next page when the end of the loaded rows comes into view.
  createEffect(() => {
    if (props.hasMore && !props.loading && !props.error && window().end >= props.rows.length - LOAD_AHEAD) {
      props.onLoadMore?.();
    }
  });

  // The selection count in the status bar.
  createEffect(() => {
    if (props.statusBar === false) return;
    const n = selection.count();
    setSelectionStatus(n > 0 ? { selected: n, total: props.rows.length } : null);
  });
  onCleanup(() => {
    if (props.statusBar !== false) setSelectionStatus(null);
  });

  onMount(() => {
    props.ref?.(table);
    const measure = () => setViewport(wrap.clientHeight || FALLBACK_VIEWPORT);
    measure();
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(measure);
      observer.observe(wrap);
      onCleanup(() => observer.disconnect());
    }
  });

  const cellId = (row: number, col: number) => `${props.id}-r${row}-c${col}`;
  const label = (row: T) => {
    if (props.rowLabel) return props.rowLabel(row);
    const first = cols()[0];
    return first?.text?.(row) ?? props.rowKey?.(row) ?? props.rowId(row);
  };

  /** The column object at a focus column index, or a marker for the extra columns. */
  const columnAt = (col: number): Column<T> | "check" | "actions" | undefined => {
    if (hasCheck() && col === 0) return "check";
    const i = col - (hasCheck() ? 1 : 0);
    if (i < cols().length) return cols()[i];
    return hasActions() ? "actions" : undefined;
  };

  // Rows are measured in "row coordinates": row i starts at i * rowHeight, which is
  // HEADER_HEIGHT further down in the scroll container. The rows visible under the sticky
  // header are those between scrollTop and scrollTop + viewport - HEADER_HEIGHT.
  const setFocusTo = (next: CellFocus) => {
    headerChosen = next.row < 0;
    setFocus(next);
    setFocusedId(next.row >= 0 ? (ids()[next.row] ?? null) : null);
    if (next.row < 0) return;
    const current = wrap.scrollTop;
    const target = scrollToShow(next.row, current, Math.max(rowHeight(), viewport() - HEADER_HEIGHT), rowHeight());
    if (target !== current) {
      wrap.scrollTop = target;
      setScrollTop(target);
    }
  };

  const activeDescendant = () => {
    if (!active()) return undefined;
    const f = focus();
    if (f.row < 0) return `${props.id}-h${f.col}`;
    const { start, end } = window();
    return f.row >= start && f.row < end ? cellId(f.row, f.col) : undefined;
  };

  const sortBy = (column: Column<T>) => {
    if (!column.sort || !props.onSort) return;
    props.onSort(nextSort(props.sort, column.sort));
  };

  const startEdit = (row: T, column: Column<T>): boolean => {
    const editor = props.editors?.[column.id];
    if (!editor || !(column.editable?.(row) ?? true)) return false;
    setEditing({ id: props.rowId(row), col: column.id });
    return true;
  };
  const stopEdit = () => {
    setEditing(null);
    queueMicrotask(() => table.focus());
  };

  const openMenu = (row: T, anchor?: HTMLElement) => {
    if (!hasActions()) return;
    const i = index().get(props.rowId(row));
    const el =
      anchor ??
      (i !== undefined ? document.getElementById(cellId(i, colCount() - 1)) : null) ??
      table;
    setMenu({ row, anchor: el });
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (editing() || (e.target !== table && isTyping(e))) return;
    const f = focus();
    const rows = props.rows;
    const row = f.row >= 0 ? rows[f.row] : undefined;
    const ctrl = e.ctrlKey || e.metaKey;

    // In a right-to-left layout the arrows move along the reading order (focus.ts).
    const key = logicalArrow(e.key, table);
    if (isMoveKey(key) && !e.altKey && !(ctrl && (key === "j" || key === "k"))) {
      if ((key === "j" || key === "k") && e.shiftKey) return;
      e.preventDefault();
      const page = Math.max(1, Math.floor((viewport() - HEADER_HEIGHT) / rowHeight()) - 1);
      const next = moveFocus(f, key, { rows: rows.length, cols: colCount(), page }, ctrl);
      setFocusTo(next);
      const target = next.row >= 0 ? rows[next.row] : undefined;
      if (e.shiftKey && target && (e.key === "ArrowDown" || e.key === "ArrowUp") && selectableRow(target)) {
        selection.extendTo(props.rowId(target));
      }
      return;
    }
    if ((e.key === " " || (e.key === "Enter" && !e.shiftKey)) && !ctrl && isToggle(row)) {
      e.preventDefault();
      props.onToggle?.(row);
      return;
    }
    if (e.key === " " && !ctrl) {
      e.preventDefault();
      if (row && selectableRow(row)) selection.toggle(props.rowId(row));
      return;
    }
    if (ctrl && e.key.toLowerCase() === "a" && !props.noSelection) {
      e.preventDefault();
      selection.selectAll();
      return;
    }
    if (e.key === "Escape" && selection.count() > 0) {
      e.preventDefault();
      e.stopPropagation();
      selection.clear();
      return;
    }
    if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
      if (row) {
        e.preventDefault();
        openMenu(row);
      }
      return;
    }
    if (e.key === "Enter") {
      if (f.row < 0) {
        const column = columnAt(f.col);
        if (column && typeof column === "object") {
          e.preventDefault();
          sortBy(column);
        } else if (column === "check") {
          e.preventDefault();
          if (selection.all()) selection.clear();
          else selection.selectAll();
        }
        return;
      }
      if (!row) return;
      e.preventDefault();
      if (e.shiftKey) {
        props.onOpenPage?.(row);
        return;
      }
      const column = columnAt(f.col);
      if (column === "actions") openMenu(row);
      else if (column === "check" && selectableRow(row)) selection.toggle(props.rowId(row));
      else if (!(column && typeof column === "object" && startEdit(row, column))) props.onOpen?.(row);
      return;
    }
    if (e.key === "." && row && !ctrl) {
      e.preventDefault();
      props.onDetails?.(row);
    }
  };

  const onRowClick = (e: MouseEvent, row: T, i: number) => {
    const target = e.target as HTMLElement;
    const cell = target.closest("td");
    const col = cell ? Number(cell.dataset.c ?? 0) : 0;
    setFocusTo({ row: i, col });
    table.focus({ preventScroll: true });
    if (target.closest("a, button, input, select, textarea")) return;
    if (isToggle(row)) {
      props.onToggle?.(row);
      return;
    }
    const id = props.rowId(row);
    if (!selectableRow(row)) return;
    if (e.shiftKey) selection.extendTo(id);
    else if (e.ctrlKey || e.metaKey) selection.toggle(id);
  };

  const onCheck = (e: MouseEvent, row: T) => {
    e.stopPropagation();
    const id = props.rowId(row);
    if (e.shiftKey) selection.extendTo(id);
    else selection.toggle(id);
  };

  const onDragStart = (e: DragEvent, row: T) => {
    if (!props.dragItems || !selectableRow(row) || !(props.draggable?.(row) ?? true)) {
      e.preventDefault();
      return;
    }
    const id = props.rowId(row);
    const rows = selection.has(id)
      ? props.rows.filter((r) => selection.has(props.rowId(r)))
      : [row];
    const items = props.dragItems(rows);
    if (!items || items.length === 0) {
      e.preventDefault();
      return;
    }
    startDrag(items);
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", items.map((x) => x.label).join("\n"));
      e.dataTransfer.setData(DRAG_MIME, JSON.stringify(items));
      const ghost = document.createElement("div");
      ghost.className = "drag-ghost";
      const head = document.createElement("div");
      head.className = "g-head";
      const n = document.createElement("span");
      n.className = "n";
      n.textContent = String(items.length);
      head.append(n, props.dragLabel?.(items) ?? "");
      ghost.append(head);
      for (const item of items.slice(0, 5)) {
        const line = document.createElement("div");
        line.className = "g-row";
        line.textContent = item.ip ? `${item.ip}  ${item.label}` : item.label;
        ghost.append(line);
      }
      document.body.append(ghost);
      e.dataTransfer.setDragImage?.(ghost, 16, 16);
      setTimeout(() => ghost.remove(), 0);
    }
  };

  const ariaSort = (column: Column<T>): "ascending" | "descending" | "none" | undefined => {
    if (!column.sort) return undefined;
    if (props.sort?.field !== column.sort) return "none";
    return props.sort.desc ? "descending" : "ascending";
  };

  const headerCheckbox = (el: HTMLInputElement) => {
    createEffect(() => {
      el.indeterminate = selection.count() > 0 && !selection.all();
    });
  };

  const isFocus = (row: number, col: number) => active() && focus().row === row && focus().col === col;
  const isEditing = (row: T, column: Column<T>) => {
    const e = editing();
    return !!e && e.col === column.id && e.id === props.rowId(row);
  };

  return (
    <div class="grid-shell" data-testid={`grid-${props.id}`}>
      <div
        ref={wrap}
        class="grid-wrap"
        classList={{ stale: slowLoading() && !props.initial }}
        onScroll={() => setScrollTop(wrap.scrollTop)}
      >
        <table
          ref={table}
          class="grid"
          role="grid"
          id={props.id}
          aria-label={props.label}
          aria-rowcount={props.hasMore ? -1 : props.rows.length + 1}
          aria-colcount={colCount()}
          aria-multiselectable={props.noSelection ? undefined : "true"}
          aria-busy={props.loading ? "true" : undefined}
          aria-activedescendant={activeDescendant()}
          style={resizer.tableWidth() ? { width: resizer.tableWidth() } : undefined}
          tabIndex={0}
          onKeyDown={onKeyDown}
          onFocus={() => setActive(true)}
          onBlur={(e) => {
            if (!table.contains(e.relatedTarget as Node | null)) setActive(false);
          }}
        >
          <colgroup>
            <Show when={hasCheck()}>
              <col class="c-check" />
            </Show>
            <For each={cols()}>
              {(c) => {
                const width = () => resizer.colWidth(c.id);
                return <col style={width() ? { width: `${width()}px` } : undefined} />;
              }}
            </For>
            <Show when={hasActions()}>
              <col class="c-acts" />
            </Show>
          </colgroup>
          <thead>
            <tr aria-rowindex={1}>
              <Show when={hasCheck()}>
                <th
                  class="check"
                  id={`${props.id}-h0`}
                  classList={{ focus: isFocus(-1, 0) }}
                  scope="col"
                >
                  <input
                    ref={headerCheckbox}
                    type="checkbox"
                    class="cb"
                    tabIndex={-1}
                    aria-label={t("grid.select_all")}
                    checked={selection.all()}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (selection.all()) selection.clear();
                      else selection.selectAll();
                    }}
                  />
                </th>
              </Show>
              <For each={cols()}>
                {(c, i) => {
                  /** The focus column of this header cell; its label's id names the column. */
                  const at = () => i() + (hasCheck() ? 1 : 0);
                  const labelId = () => `${props.id}-h${at()}-label`;
                  return (
                    <th
                      scope="col"
                      id={`${props.id}-h${at()}`}
                      aria-sort={ariaSort(c)}
                      // The header text names the column, not the resize handle inside the cell.
                      aria-labelledby={labelId()}
                      classList={{ r: c.align === "right", focus: isFocus(-1, at()) }}
                      data-col={c.id}
                    >
                      <Show
                        when={c.sort && props.onSort}
                        fallback={
                          <span id={labelId()}>
                            {c.header()}
                            <Majority value={majorities().get(c.id)} />
                          </span>
                        }
                      >
                        <button type="button" class="th-sort" tabIndex={-1} onClick={() => sortBy(c)}>
                          <span id={labelId()}>
                            {c.header()}
                            <Majority value={majorities().get(c.id)} />
                          </span>
                          <Show when={props.sort?.field === c.sort}>
                            <Icon name={props.sort?.desc ? "chev-d" : "chev-u"} size="xs" />
                          </Show>
                        </button>
                      </Show>
                      <Show when={resizer.enabled()}>
                        <ColumnResize
                          resizer={resizer}
                          column={c.id}
                          label={t("grid.resize.handle", { column: c.header() })}
                          tabbable={focus().col === at()}
                          onEnd={() => table.focus({ preventScroll: true })}
                        />
                      </Show>
                    </th>
                  );
                }}
              </For>
              <Show when={hasActions()}>
                <th class="acts" scope="col" id={`${props.id}-h${colCount() - 1}`}>
                  <span class="sr-only">{t("grid.actions")}</span>
                </th>
              </Show>
            </tr>
          </thead>
          <tbody>
            <Show when={window().start > 0}>
              <tr class="spacer" aria-hidden="true">
                <td colSpan={span()} style={{ height: `${window().start * rowHeight()}px` }} />
              </tr>
            </Show>
            <For each={windowRows()}>
              {(entry) => {
                const row = entry.row;
                const i = entry.index;
                const id = props.rowId(row);
                const full = props.fullRow?.(row) ?? null;
                const selectable = selectableRow(row);
                return (
                  <tr
                    data-testid="row"
                    data-id={id}
                    data-key={props.rowKey?.(row)}
                    aria-rowindex={i + 2}
                    aria-selected={selectable ? selection.has(id) : undefined}
                    data-expanded={props.expanded?.(row)}
                    class={props.rowClass?.(row)}
                    classList={{ flash: props.flashed?.(id) ?? false }}
                    draggable={!!props.dragItems && selectable && (props.draggable?.(row) ?? true)}
                    onClick={(e) => onRowClick(e, row, i)}
                    onDblClick={(e) => {
                      if ((e.target as HTMLElement).closest("a, button, input, select")) return;
                      const cell = (e.target as HTMLElement).closest("td");
                      const column = columnAt(Number(cell?.dataset.c ?? -1));
                      if (!(column && typeof column === "object" && startEdit(row, column))) props.onOpen?.(row);
                    }}
                    onDragStart={(e) => onDragStart(e, row)}
                    onDragEnd={() => endDrag()}
                  >
                    <Show when={hasCheck()}>
                      <td class="check" role="gridcell" id={cellId(i, 0)} data-c="0" classList={{ focus: isFocus(i, 0) }}>
                        <Show when={selectable}>
                          <input
                            type="checkbox"
                            class="cb"
                            tabIndex={-1}
                            aria-label={t("grid.select_row", { row: label(row) })}
                            checked={selection.has(id)}
                            onClick={(e) => onCheck(e, row)}
                          />
                        </Show>
                      </td>
                    </Show>
                    <Switch>
                      <Match when={full !== null}>
                        <td
                          role="gridcell"
                          class="full"
                          colSpan={cols().length}
                          id={cellId(i, hasCheck() ? 1 : 0)}
                          data-c={hasCheck() ? 1 : 0}
                          classList={{ focus: active() && focus().row === i && focus().col >= (hasCheck() ? 1 : 0) }}
                        >
                          {full}
                        </td>
                      </Match>
                      <Match when={full === null}>
                        <For each={cols()}>
                          {(c, ci) => {
                            const col = () => ci() + (hasCheck() ? 1 : 0);
                            return (
                              <td
                                role="gridcell"
                                id={cellId(i, col())}
                                data-c={col()}
                                data-col={c.id}
                                class={c.class}
                                classList={{
                                  r: c.align === "right",
                                  focus: isFocus(i, col()),
                                  editing: isEditing(row, c),
                                }}
                              >
                                <Show when={isEditing(row, c)} fallback={majorities().has(c.id) ? null : c.render(row)}>
                                  {props.editors?.[c.id]?.({ row, close: stopEdit })}
                                </Show>
                              </td>
                            );
                          }}
                        </For>
                      </Match>
                    </Switch>
                    <Show when={hasActions()}>
                      <td class="acts" role="gridcell" id={cellId(i, colCount() - 1)} data-c={colCount() - 1} classList={{ focus: isFocus(i, colCount() - 1) }}>
                        <Show when={full === null}>
                          <button
                            type="button"
                            class="icon-btn row-menu"
                            tabIndex={-1}
                            aria-haspopup="menu"
                            aria-label={t("grid.row_actions", { row: label(row) })}
                            onClick={(e) => {
                              e.stopPropagation();
                              openMenu(row, e.currentTarget);
                            }}
                          >
                            <Icon name="more" />
                          </button>
                        </Show>
                      </td>
                    </Show>
                  </tr>
                );
              }}
            </For>
            <Show when={window().end < props.rows.length}>
              <tr class="spacer" aria-hidden="true">
                <td colSpan={span()} style={{ height: `${(props.rows.length - window().end) * rowHeight()}px` }} />
              </tr>
            </Show>
            <Show when={props.loading && slowLoading() && (props.initial || props.rows.length === 0 || props.hasMore)}>
              <tr class="loading-row">
                <td colSpan={span()} role="gridcell">
                  <span role="status">{props.rows.length ? t("grid.loading_more") : t("grid.loading")}</span>
                </td>
              </tr>
            </Show>
          </tbody>
        </table>
        <Show when={!props.initial && !props.loading && !props.error && props.rows.length === 0}>
          <div class="grid-empty" data-testid="grid-empty">
            {props.empty ?? (
              <div class="empty">
                <h3>{t("grid.empty.title")}</h3>
              </div>
            )}
          </div>
        </Show>
        <Show when={props.error}>
          <div class="grid-error">
            <ErrorNotice error={props.error} />
            <Show when={props.onRetry}>
              <button type="button" class="btn" onClick={() => props.onRetry?.()}>
                {t("common.action.retry")}
              </button>
            </Show>
          </div>
        </Show>
      </div>
      <div class="grid-foot" data-testid="grid-foot">
        <span title={props.count?.title} data-testid="grid-count">
          <Show when={props.count} fallback={<><Si value={props.rows.length} /> {t("grid.rows", { count: props.rows.length })}</>}>
            {(count) => (
              <>
                <Si value={count().value} /> {count().noun}
              </>
            )}
          </Show>
          <Show when={props.hasMore}>
            <span class="muted"> {t("grid.more")}</span>
          </Show>
        </span>
        <Show when={selection.count() > 0}>
          <span>{t("grid.selected", { count: selection.count() })}</span>
        </Show>
        {props.footer}
        <Show when={widths.custom() && !widths.menu()}>
          <button type="button" class="btn sm ghost grid-reset-widths" data-testid="grid-reset-widths" onClick={() => widths.reset()}>
            {t("grid.resize.reset")}
          </button>
        </Show>
      </div>
      <Show when={menu()}>
        {(m) => {
          const { row, anchor } = m();
          return (
            <Menu
              anchor={anchor}
              label={t("grid.row_actions", { row: label(row) })}
              testid="row-menu"
              onClose={() => setMenu(null)}
              items={(props.rowActions ?? []).filter((a) => !a.hidden?.(row)).map((a) => ({
                id: a.id,
                label: a.label(),
                danger: a.danger,
                disabled: a.disabled?.(row) ?? false,
                run: () => a.run(row),
              }))}
            />
          );
        }}
      </Show>
    </div>
  );
}
