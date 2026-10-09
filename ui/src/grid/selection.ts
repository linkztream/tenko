// The selection of a grid: a set of row ids plus an anchor for Shift ranges, kept apart from
// the cell focus (design/README.md, notes for the implementation). Only selectable rows can
// be selected (a free gap or a group row cannot). Ids that leave the list leave the
// selection, so a count never includes rows that are gone.
import { createMemo, createSignal, type Accessor } from "solid-js";

/** The ids from `a` to `b` inclusive, in list order (either may come first). */
export function idsBetween(ids: readonly string[], a: string, b: string): string[] {
  const i = ids.indexOf(a);
  const j = ids.indexOf(b);
  if (i < 0 || j < 0) return j >= 0 ? [b] : [];
  const [lo, hi] = i <= j ? [i, j] : [j, i];
  return ids.slice(lo, hi + 1);
}

export interface Selection {
  /** Selected ids in list order. */
  ids: Accessor<string[]>;
  count: Accessor<number>;
  has: (id: string) => boolean;
  /** Toggles one row and makes it the anchor. */
  toggle: (id: string) => void;
  /** Adds the rows from the anchor to `id` (Shift+click, Shift+arrow). */
  extendTo: (id: string) => void;
  /** Replaces the selection. */
  set: (ids: readonly string[]) => void;
  selectAll: () => void;
  clear: () => void;
  /** Every selectable row is selected (and there is at least one). */
  all: Accessor<boolean>;
}

/** A selection over the selectable ids of a list (call inside a component or a root). */
export function createSelection(selectable: Accessor<readonly string[]>): Selection {
  const [chosen, setChosen] = createSignal<ReadonlySet<string>>(new Set());
  let anchor: string | null = null;

  const ids = createMemo(() => {
    const set = chosen();
    if (set.size === 0) return [];
    return selectable().filter((id) => set.has(id));
  });
  const lookup = createMemo(() => new Set(ids()));

  const write = (next: Iterable<string>) => setChosen(new Set(next));

  return {
    ids,
    count: () => ids().length,
    has: (id) => lookup().has(id),
    toggle(id) {
      if (!selectable().includes(id)) return;
      const next = new Set(chosen());
      if (next.has(id)) next.delete(id);
      else next.add(id);
      anchor = id;
      setChosen(next);
    },
    extendTo(id) {
      const list = selectable();
      if (!list.includes(id)) return;
      const from = anchor !== null && list.includes(anchor) ? anchor : id;
      anchor = from;
      write([...ids(), ...idsBetween(list, from, id)]);
    },
    set(next) {
      const allowed = new Set(selectable());
      const list = next.filter((id) => allowed.has(id));
      anchor = list[list.length - 1] ?? null;
      write(list);
    },
    selectAll() {
      write(selectable());
    },
    clear() {
      anchor = null;
      write([]);
    },
    all: () => selectable().length > 0 && ids().length === selectable().length,
  };
}
