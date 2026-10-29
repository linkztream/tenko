// Column widths of a list: dragged, stepped with the keyboard or fitted to the content on the
// handle at the trailing edge of a header cell (ColumnResize.tsx). They are saved per list and
// per signed-in user in the table's layout (layoutStore.ts: on the server under `table:<list
// id>`, with the browser's copy while the server is out of reach), beside the column order and
// visibility of prefs.ts; "Reset column widths" drops only them. Stored widths are clamped to the
// bounds and, when the list says which columns it has, limited to those. A narrow screen (the
// phone layout of the forms, 560 px) ignores stored widths and offers no handles: the default
// layout of the list applies there.
//
// Layout: the tables keep `table-layout: fixed`. Once a width is stored, every column but the
// last has a width in pixels (the ones the user did not touch are frozen at the width they had
// when the first resize started, so nothing jumps) and the last column takes the remaining
// width. The table is never narrower than the sum, so a wide set of columns scrolls
// horizontally inside its wrapper instead of squeezing the last column away.
import { createSignal, getOwner, onCleanup, untrack, type Accessor } from "solid-js";
import { session } from "../auth/session";
import { LEGACY_WIDTHS, patchLayout, tableLayout } from "./layoutStore";

/** Narrowest a column can be made, in pixels. */
export const MIN_WIDTH = 48;
/** Widest a column can be made, in pixels. */
export const MAX_WIDTH = 1200;
/** Arrow key step, and the step with Shift. */
export const STEP = 8;
export const BIG_STEP = 40;
/** Width of a column without a default width once the widths are fixed. */
export const DEFAULT_WIDTH = 160;
/** The phone layout (forms.css, provision.css): stored widths do not apply there. */
export const NARROW_QUERY = "(max-width: 560px)";


export type WidthMap = Readonly<Record<string, number>>;

/** `width` within the bounds, in whole pixels. */
export function clampWidth(width: number, min = MIN_WIDTH): number {
  if (!Number.isFinite(width)) return min;
  return Math.round(Math.min(MAX_WIDTH, Math.max(min, width)));
}

/**
 * The width after a drag from `startX` to `x`. The handle sits on the trailing edge, so the
 * column grows to the right left to right and to the left right to left.
 */
export function dragWidth(start: number, startX: number, x: number, rtl: boolean, min = MIN_WIDTH): number {
  return clampWidth(start + (rtl ? startX - x : x - startX), min);
}

/**
 * The width after an arrow key, or null for a key that does not resize. The arrow that points
 * away from the column (right left to right, left right to left) widens it.
 */
export function keyWidth(width: number, key: string, shift: boolean, rtl: boolean, min = MIN_WIDTH): number | null {
  if (key !== "ArrowLeft" && key !== "ArrowRight") return null;
  const grow = rtl ? key === "ArrowLeft" : key === "ArrowRight";
  const step = shift ? BIG_STEP : STEP;
  return clampWidth(width + (grow ? step : -step), min);
}

/** The width that shows the widest of the measured contents (header and cells) in full. */
export function fitWidth(naturals: readonly number[], min = MIN_WIDTH): number {
  const widest = naturals.reduce((a, b) => (Number.isFinite(b) && b > a ? b : a), 0);
  return clampWidth(Math.ceil(widest) + 1, min);
}

/** The key of the widths of list `listId` for user `user` in the browser store before U6 (imported once). */
export function widthsKey(listId: string, user: string | null | undefined): string {
  return `${LEGACY_WIDTHS}${user ?? "-"}:${listId}`;
}

/** The stored widths, or null; values that are not positive numbers are dropped. */
export function readWidths(key: string): Record<string, number> | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const v: unknown = JSON.parse(raw);
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    const out: Record<string, number> = {};
    for (const [id, w] of Object.entries(v as Record<string, unknown>)) {
      if (typeof w === "number" && Number.isFinite(w) && w > 0) out[id] = clampWidth(w);
    }
    return Object.keys(out).length > 0 ? out : null;
  } catch {
    return null;
  }
}

export function writeWidths(key: string, widths: WidthMap | null): void {
  try {
    if (widths === null || Object.keys(widths).length === 0) localStorage.removeItem(key);
    else localStorage.setItem(key, JSON.stringify(widths));
  } catch {
    // Storage unavailable: the widths last for this page only.
  }
}

function narrowQuery(): MediaQueryList | undefined {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(NARROW_QUERY)
    : undefined;
}

export interface ColumnWidths {
  /** The stored width of a column; undefined when none is stored or on a narrow screen. */
  get: (id: string) => number | undefined;
  /** Whether stored widths are in effect. */
  custom: Accessor<boolean>;
  /** The screen is narrow: stored widths are ignored and the handles are left out. */
  narrow: Accessor<boolean>;
  /** Sets widths for this page (during a drag); `commit` stores them. */
  update: (patch: WidthMap) => void;
  commit: () => void;
  /** Drops every stored width of the list. */
  reset: () => void;
  /** Whether a column menu of the list offers the reset (else the grid footer does). */
  menu: Accessor<boolean>;
  /** A column menu registers itself; the returned function unregisters it. */
  attachMenu: () => () => void;
}

/** The stored widths within the bounds, of the known columns only when `known` is given. */
export function boundWidths(widths: Readonly<Record<string, number>> | undefined, known?: readonly string[]): Record<string, number> {
  const out: Record<string, number> = {};
  const ids = known ? new Set(known) : null;
  for (const [id, w] of Object.entries(widths ?? {})) {
    if (typeof w === "number" && Number.isFinite(w) && w > 0 && (!ids || ids.has(id))) out[id] = clampWidth(w);
  }
  return out;
}

/**
 * The widths of list `listId` for the signed-in user (call inside a component). `known` names the
 * columns of the list; a stored width of another column is ignored.
 */
export function createColumnWidths(
  listId: string,
  user = untrack(() => session()?.user.id),
  known?: () => readonly string[],
): ColumnWidths {
  const layout = tableLayout(user, listId);
  const stored = () => boundWidths(layout()?.widths, known?.());
  // The widths of a drag in progress, until `commit` stores them.
  const [draft, setDraft] = createSignal<WidthMap | null>(null);
  const map = () => draft() ?? stored();
  const query = narrowQuery();
  const [narrow, setNarrow] = createSignal(query?.matches ?? false);
  if (query) {
    const onChange = (e: MediaQueryListEvent) => setNarrow(e.matches);
    query.addEventListener?.("change", onChange);
    if (getOwner()) onCleanup(() => query.removeEventListener?.("change", onChange));
  }
  const [menus, setMenus] = createSignal(0);

  return {
    get: (id) => (narrow() ? undefined : map()[id]),
    custom: () => !narrow() && Object.keys(map()).length > 0,
    narrow,
    update(patch) {
      const next: Record<string, number> = { ...map() };
      for (const [id, w] of Object.entries(patch)) next[id] = clampWidth(w);
      setDraft(next);
    },
    commit() {
      const next = draft();
      setDraft(null);
      if (next) patchLayout(user, listId, { widths: Object.keys(next).length > 0 ? { ...next } : undefined });
    },
    reset() {
      setDraft(null);
      patchLayout(user, listId, { widths: undefined });
    },
    menu: () => menus() > 0,
    attachMenu() {
      setMenus((n) => n + 1);
      return () => setMenus((n) => n - 1);
    },
  };
}
