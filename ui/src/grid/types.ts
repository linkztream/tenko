// Types of the data grid (see DataGrid.tsx). A column renders one cell per row; `sort`
// names the server's sort field (`sort=<field>` or `sort=-<field>` on list endpoints), so a
// sortable column always sorts on the server, never in the browser.
import type { JSX } from "solid-js";

export interface Column<T> {
  /** Stable id: the `data-col` attribute of its cells and the key of the column preferences. */
  id: string;
  /** Translated header text; a function so it follows a language switch. */
  header: () => string;
  /** Fixed width in pixels; columns without one share the remaining space. */
  width?: number;
  /** The server's sort field; absent when the column cannot be sorted. */
  sort?: string;
  align?: "right";
  /** Extra class of every cell of the column. */
  class?: string;
  render: (row: T) => JSX.Element;
  /** The cell as plain text, for the accessible row name and copying. */
  text?: (row: T) => string;
  /** Hidden until the user shows it in the column chooser. */
  hidden?: boolean;
  /** Always shown; the column chooser cannot hide it. */
  fixed?: boolean;
  /** Whether Enter edits this cell of `row` (the grid calls `onEdit`). */
  editable?: (row: T) => boolean;
}

export interface SortState {
  field: string;
  desc: boolean;
}

/** `sort` query value of the list endpoints: `field` or `-field`. */
export function sortParam(sort: SortState | null | undefined): string | undefined {
  return sort ? `${sort.desc ? "-" : ""}${sort.field}` : undefined;
}

/** The next sort after a click on a column header: ascending, descending, then off. */
export function nextSort(current: SortState | null | undefined, field: string): SortState | null {
  if (!current || current.field !== field) return { field, desc: false };
  if (!current.desc) return { field, desc: true };
  return null;
}

/** An action on one row, shown in the row's menu (also opened with the context-menu key). */
export interface RowAction<T> {
  id: string;
  label: () => string;
  run: (row: T) => void;
  danger?: boolean;
  disabled?: (row: T) => boolean;
  /** Leaves the action out of the row's menu (an action the principal may not use on this row). */
  hidden?: (row: T) => boolean;
}
