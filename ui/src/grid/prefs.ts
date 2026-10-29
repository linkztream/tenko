// Column visibility and order of each grid, saved per user with the rest of the table's layout
// (layoutStore.ts: on the server under `table:<grid id>`, with the browser's copy while the
// server is out of reach). A column the stored order does not know (a newer UI) keeps its
// default place, and ids the grid does not have are ignored, so a stored document never names a
// column that does not exist. The column widths live in the same document (widths.ts) and come
// with the state so the column menu can reset them; "Reset columns" returns the whole table to
// its default.
import { untrack, type Accessor } from "solid-js";
import { session } from "../auth/session";
import { patchLayout, resetLayout, tableLayout, type LayoutSort } from "./layoutStore";
import type { Column } from "./types";
import { createColumnWidths, type ColumnWidths } from "./widths";

export interface ColumnPrefs {
  order: string[];
  hidden: string[];
}

/** Orders `columns` by `order`; unknown columns keep their default position. */
export function orderColumns<T>(columns: readonly Column<T>[], order: readonly string[]): Column<T>[] {
  const rank = new Map(order.map((id, i) => [id, i]));
  const known = columns.filter((c) => rank.has(c.id)).sort((a, b) => (rank.get(a.id) ?? 0) - (rank.get(b.id) ?? 0));
  const out: Column<T>[] = [];
  let k = 0;
  for (const column of columns) {
    if (rank.has(column.id)) {
      const next = known[k++];
      if (next) out.push(next);
    } else out.push(column);
  }
  return out;
}

export interface ColumnState<T> {
  /** Every column in the user's order. */
  all: Accessor<Column<T>[]>;
  /** The visible columns in order. */
  visible: Accessor<Column<T>[]>;
  isHidden: (id: string) => boolean;
  setHidden: (id: string, hidden: boolean) => void;
  /** Moves a column one place earlier (-1) or later (+1). */
  move: (id: string, delta: -1 | 1) => void;
  /** Returns the table to its default layout: order, visibility, widths and sort. */
  reset: () => void;
  /** The column widths the user set. */
  widths: ColumnWidths;
  /** The sort the user chose, when the view keeps it with the layout (a known column only). */
  sort: Accessor<LayoutSort | null>;
  saveSort: (sort: LayoutSort | null) => void;
}

/** Column state for the grid `id` (call inside a component). */
export function createColumnState<T>(id: string, columns: Accessor<readonly Column<T>[]>): ColumnState<T> {
  const user = untrack(() => session()?.user.id);
  const layout = tableLayout(user, id);
  const known = () => new Set(columns().map((c) => c.id));
  const defaultsHidden = () => columns().filter((c) => c.hidden).map((c) => c.id);
  /** The stored order and visibility, reduced to the columns this grid has. */
  const prefs = (): ColumnPrefs | null => {
    const l = layout();
    if (!l?.order && !l?.hidden) return null;
    const ids = known();
    const fixed = new Set(columns().filter((c) => c.fixed).map((c) => c.id));
    return {
      order: (l.order ?? []).filter((c) => ids.has(c)),
      hidden: l.hidden ? l.hidden.filter((c) => ids.has(c) && !fixed.has(c)) : defaultsHidden(),
    };
  };

  const hidden = () => new Set(prefs()?.hidden ?? defaultsHidden());
  const all = () => orderColumns(columns(), prefs()?.order ?? []);
  const update = (next: ColumnPrefs) => patchLayout(user, id, { order: next.order, hidden: next.hidden });
  const current = (): ColumnPrefs => ({ order: all().map((c) => c.id), hidden: [...hidden()] });

  return {
    all,
    visible: () => all().filter((c) => c.fixed || !hidden().has(c.id)),
    isHidden: (cid) => hidden().has(cid),
    setHidden(cid, value) {
      const column = columns().find((c) => c.id === cid);
      if (!column || column.fixed) return;
      const next = current();
      const set = new Set(next.hidden);
      if (value) set.add(cid);
      else set.delete(cid);
      update({ ...next, hidden: [...set] });
    },
    move(cid, delta) {
      const order = current().order;
      const i = order.indexOf(cid);
      const j = i + delta;
      if (i < 0 || j < 0 || j >= order.length) return;
      [order[i], order[j]] = [order[j] as string, order[i] as string];
      update({ ...current(), order });
    },
    reset: () => resetLayout(user, id),
    widths: createColumnWidths(id, user, () => [...known()]),
    sort: () => {
      const s = layout()?.sort;
      return s && known().has(s.column) ? s : null;
    },
    saveSort: (sort) => patchLayout(user, id, { sort: sort ?? undefined }),
  };
}
