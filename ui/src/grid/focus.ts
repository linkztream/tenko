// The cell focus of a grid: a row index (-1 is the header row) and a column index
// (0 is the selection column when the grid has one), and the window of rendered rows.
// Pure, so the keyboard map and the virtualization are testable without layout. Keys
// follow design/README.md, "Keyboard map".

export interface CellFocus {
  row: number;
  col: number;
}

export interface FocusBounds {
  rows: number;
  cols: number;
  /** Rows that fit in the viewport, for Page Up and Page Down. */
  page: number;
}

/** Keys the grid moves the focus with. */
export type MoveKey =
  | "ArrowDown"
  | "ArrowUp"
  | "ArrowLeft"
  | "ArrowRight"
  | "Home"
  | "End"
  | "PageDown"
  | "PageUp"
  | "j"
  | "k";

const MOVE: ReadonlySet<string> = new Set([
  "ArrowDown",
  "ArrowUp",
  "ArrowLeft",
  "ArrowRight",
  "Home",
  "End",
  "PageDown",
  "PageUp",
  "j",
  "k",
]);

export function isMoveKey(key: string): key is MoveKey {
  return MOVE.has(key);
}

/** Whether `el` is laid out right to left: the nearest `dir` attribute decides, as in bidi.css. */
export function isRtl(el: Element | null | undefined): boolean {
  return el?.closest("[dir]")?.getAttribute("dir")?.toLowerCase() === "rtl";
}

/**
 * The arrow key as the left-to-right keyboard map means it. In a right-to-left layout the
 * column after the current one sits on the left, so ArrowLeft moves forward and ArrowRight
 * back; the two swap there. Every other key is returned unchanged.
 */
export function logicalArrow(key: string, el: Element | null | undefined): string {
  if ((key !== "ArrowLeft" && key !== "ArrowRight") || !isRtl(el)) return key;
  return key === "ArrowLeft" ? "ArrowRight" : "ArrowLeft";
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

/** Where the focus goes for `key`; with `ctrl`, Home and End jump to the first or last row. */
export function moveFocus(focus: CellFocus, key: MoveKey, bounds: FocusBounds, ctrl = false): CellFocus {
  const lastRow = bounds.rows - 1;
  const lastCol = Math.max(0, bounds.cols - 1);
  const col = clamp(focus.col, 0, lastCol);
  const row = (r: number) => clamp(r, -1, Math.max(-1, lastRow));
  switch (key) {
    case "ArrowDown":
    case "j":
      return { row: row(focus.row + 1), col };
    case "ArrowUp":
    case "k":
      return { row: row(focus.row - 1), col };
    case "ArrowLeft":
      return { row: focus.row, col: clamp(col - 1, 0, lastCol) };
    case "ArrowRight":
      return { row: focus.row, col: clamp(col + 1, 0, lastCol) };
    case "Home":
      return ctrl ? { row: lastRow >= 0 ? 0 : -1, col } : { row: focus.row, col: 0 };
    case "End":
      return ctrl ? { row: lastRow, col } : { row: focus.row, col: lastCol };
    case "PageDown":
      return { row: row(focus.row + Math.max(1, bounds.page)), col };
    case "PageUp":
      return { row: clamp(focus.row - Math.max(1, bounds.page), lastRow >= 0 ? 0 : -1, Math.max(-1, lastRow)), col };
  }
}

/** The rows to render for a scroll position: a window with `overscan` rows on each side. */
export function visibleWindow(
  scrollTop: number,
  viewport: number,
  rowHeight: number,
  total: number,
  overscan = 8,
): { start: number; end: number } {
  if (total <= 0 || rowHeight <= 0) return { start: 0, end: 0 };
  const first = Math.floor(Math.max(0, scrollTop) / rowHeight);
  const count = Math.ceil(Math.max(0, viewport) / rowHeight);
  const start = clamp(first - overscan, 0, total);
  const end = clamp(first + count + overscan, start, total);
  return { start, end };
}

/** The scroll position that shows row `index` (unchanged when it is visible already). */
export function scrollToShow(index: number, scrollTop: number, viewport: number, rowHeight: number): number {
  const top = index * rowHeight;
  const bottom = top + rowHeight;
  if (top < scrollTop) return top;
  if (bottom > scrollTop + viewport) return Math.max(0, bottom - viewport);
  return scrollTop;
}

/** Row height in pixels for each density (design/README.md, "Spacing and density"). */
export const ROW_HEIGHT = { dense: 24, compact: 28, comfortable: 34 } as const;
