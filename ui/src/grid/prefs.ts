// Column visibility and order of each grid, remembered per browser under
// `tenko-grid:<grid id>` in localStorage (like theme and density in app/prefs.ts). A column
// the stored order does not know (a newer UI) keeps its default place. The column widths
// live apart, per user (widths.ts), and come with the state so the column menu can reset them.
import { createSignal, type Accessor } from "solid-js";
import type { Column } from "./types";
import { createColumnWidths, type ColumnWidths } from "./widths";

export interface ColumnPrefs {
  order: string[];
  hidden: string[];
}

const KEY = "tenko-grid:";

function read(id: string): ColumnPrefs | null {
  try {
    const raw = localStorage.getItem(KEY + id);
    if (!raw) return null;
    const v = JSON.parse(raw) as Partial<ColumnPrefs>;
    return {
      order: Array.isArray(v.order) ? v.order.filter((x): x is string => typeof x === "string") : [],
      hidden: Array.isArray(v.hidden) ? v.hidden.filter((x): x is string => typeof x === "string") : [],
    };
  } catch {
    return null;
  }
}

function write(id: string, prefs: ColumnPrefs | null): void {
  try {
    if (prefs === null) localStorage.removeItem(KEY + id);
    else localStorage.setItem(KEY + id, JSON.stringify(prefs));
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
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
  reset: () => void;
  /** The column widths the user set. */
  widths: ColumnWidths;
}

/** Column state for the grid `id` (call inside a component). */
export function createColumnState<T>(id: string, columns: Accessor<readonly Column<T>[]>): ColumnState<T> {
  const stored = read(id);
  const defaultsHidden = () => columns().filter((c) => c.hidden).map((c) => c.id);
  const [prefs, setPrefs] = createSignal<ColumnPrefs | null>(stored);

  const hidden = () => new Set(prefs()?.hidden ?? defaultsHidden());
  const all = () => orderColumns(columns(), prefs()?.order ?? []);
  const update = (next: ColumnPrefs | null) => {
    setPrefs(next);
    write(id, next);
  };
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
    reset: () => update(null),
    widths: createColumnWidths(id),
  };
}
