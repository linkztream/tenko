// Group rows of the data grid (GroupedGrid.tsx): the model, kept apart from the component so it
// is tested without layout. A group collapses a run of similar rows into one 28 px row with its
// label, its count and the sentence that would otherwise repeat on every row (design/README.md,
// principles 7 and 9). Whether a group is open is kept per grid and group key for the session
// (sessionStorage, so a reload keeps it and a new tab starts from the defaults); a group the
// person never touched follows its `collapsed` default.
import { createSignal, type JSX } from "solid-js";

export interface RowGroup<T> {
  /** Stable key within the grid; the open or closed state is kept under it. */
  key: string;
  /** What the group is, drawn before its count ("Act now", "Review · Unknown devices"). */
  label: JSX.Element;
  /** The label as plain text, for the accessible name of the row and its button. */
  text: string;
  /** How many rows the group holds; may exceed `rows` while more pages are to come. */
  count: number;
  /** More rows of the group may follow (the count gets a "+"). */
  more?: boolean | undefined;
  /** A short line of what the group means. */
  note?: string | undefined;
  /** The sentence every row of the group shares, said once here instead of on every row. */
  sentence?: string | undefined;
  /** The rows, in their order. */
  rows: readonly T[];
  /** Closed by default, until the person opens it this session. */
  collapsed?: boolean | undefined;
  /** An extra class of the group row, such as its severity (`act`, `review`, `info`). */
  tone?: string | undefined;
  /** A last row of the open group drawn as one wide cell, such as a "Show more" button. */
  tail?: (() => JSX.Element) | undefined;
}

/** One line of a grouped grid: the group row, a row of a group, or the tail of an open group. */
export type GroupedItem<T> =
  | { type: "group"; key: string; group: RowGroup<T>; open: boolean }
  | { type: "row"; key: string; row: T }
  | { type: "tail"; key: string; group: RowGroup<T> };

const STORE = "tenko-grid-groups:";

function readStored(grid: string): Record<string, boolean> {
  try {
    const raw = sessionStorage.getItem(STORE + grid);
    if (!raw) return {};
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== "object") return {};
    return Object.fromEntries(Object.entries(value).filter((e): e is [string, boolean] => typeof e[1] === "boolean"));
  } catch {
    return {};
  }
}

function writeStored(grid: string, state: Readonly<Record<string, boolean>>): void {
  try {
    sessionStorage.setItem(STORE + grid, JSON.stringify(state));
  } catch {
    // Storage unavailable: the choice lasts while the page is open.
  }
}

/** Choices made in this page, for when the session storage cannot keep them. */
const memory = new Map<string, Record<string, boolean>>();

export interface GroupState {
  /** Whether the group `key` is open; `collapsed` is its default. */
  isOpen: (key: string, collapsed?: boolean) => boolean;
  /** Opens a closed group and closes an open one. */
  toggle: (key: string, collapsed?: boolean) => void;
}

/** The open or closed state of the groups of the grid `grid` for this session. */
export function createGroupState(grid: string): GroupState {
  const [chosen, setChosen] = createSignal<Record<string, boolean>>({ ...readStored(grid), ...memory.get(grid) });
  const isOpen = (key: string, collapsed = false) => chosen()[key] ?? !collapsed;
  return {
    isOpen,
    toggle(key, collapsed) {
      const next = { ...chosen(), [key]: !isOpen(key, collapsed) };
      setChosen(next);
      memory.set(grid, next);
      writeStored(grid, next);
    },
  };
}

/** Forgets the choices of every grid; for tests. */
export function resetGroupStateForTest(): void {
  memory.clear();
  try {
    for (const key of Object.keys(sessionStorage)) if (key.startsWith(STORE)) sessionStorage.removeItem(key);
  } catch {
    // Nothing stored.
  }
}

/**
 * The lines of the grid: each group that holds rows (or a tail) as a group row, followed by its
 * rows and its tail while it is open. `rowItem` gives the item of a row, so a row keeps one item
 * object (and the grid one DOM row) while the groups change around it.
 */
export function flattenGroups<T>(groups: readonly RowGroup<T>[], isOpen: (group: RowGroup<T>) => boolean, rowItem: (row: T) => GroupedItem<T>): GroupedItem<T>[] {
  const out: GroupedItem<T>[] = [];
  for (const group of groups) {
    if (group.rows.length === 0 && !group.tail && group.count === 0) continue;
    const open = isOpen(group);
    out.push({ type: "group", key: group.key, group, open });
    if (!open) continue;
    for (const row of group.rows) out.push(rowItem(row));
    if (group.tail) out.push({ type: "tail", key: group.key, group });
  }
  return out;
}

/**
 * The value every row shares, or undefined when two rows differ, one has none, or there are
 * no rows: the sentence a group row says once (principle 9).
 */
export function sharedValue<T>(rows: readonly T[], of: (row: T) => string | undefined): string | undefined {
  let shared: string | undefined;
  for (const row of rows) {
    const value = of(row);
    if (value === undefined || value === "" || (shared !== undefined && value !== shared)) return undefined;
    shared = value;
  }
  return shared;
}
