// The resize handle on the trailing edge of a header cell, and the glue between a table and
// its stored widths (widths.ts). Used by the data grid and by plain tables that list rows.
//
// - Mouse, pen and touch drag the handle (pointer events with pointer capture); a double
//   click or a double tap fits the column to the widest content in view.
// - The handle is a focusable vertical separator named "Resize column <name>": the arrow keys
//   resize it in steps (Shift for larger steps), Enter or Escape ends and gives the focus back.
//   Every other key except Tab and shortcuts with Ctrl, Alt or Meta stops at the handle.
import { createSignal, onCleanup } from "solid-js";
import { isRtl } from "./focus";
import {
  clampWidth,
  DEFAULT_WIDTH,
  dragWidth,
  fitWidth,
  keyWidth,
  MAX_WIDTH,
  MIN_WIDTH,
  type ColumnWidths,
} from "./widths";
import "./resize.css";

/** A column as the resizer sees it: its id (`data-col` of its cells) and default width. */
export interface ResizableColumn {
  id: string;
  width?: number;
}

export interface Resizer {
  /** Handles are offered (not on a narrow screen). */
  enabled: () => boolean;
  /** The width of the `<col>` of a column, or undefined to let it share the remaining space. */
  colWidth: (id: string) => number | undefined;
  /** The inline `width` of the table, or undefined for the default. */
  tableWidth: () => string | undefined;
  /** The width the handle reports: the stored, measured or default width. */
  width: (id: string) => number;
  /** Starts a resize: fixes the other columns at their current widths and returns this one's. */
  start: (id: string) => number;
  resize: (id: string, width: number) => void;
  commit: () => void;
  /** Fits a column to its content in view and stores it. */
  fit: (id: string) => void;
}

/** Pixel width of an element as laid out (0 under test, where nothing is laid out). */
function laidOut(el: Element | null | undefined): number {
  return el ? Math.round(el.getBoundingClientRect().width) : 0;
}

/**
 * The width the content of a cell needs on one line: the union of its children's boxes
 * (without the resize handle) plus the inline padding of the cell.
 */
export function contentWidth(cell: HTMLElement): number {
  let start = Infinity;
  let end = -Infinity;
  for (const node of Array.from(cell.childNodes)) {
    if (node instanceof HTMLElement && node.classList.contains("col-resize")) continue;
    let rect: DOMRect | undefined;
    if (node instanceof Element) rect = node.getBoundingClientRect();
    else if (node.nodeType === Node.TEXT_NODE && node.textContent?.trim()) {
      const range = document.createRange();
      range.selectNodeContents(node);
      rect = typeof range.getBoundingClientRect === "function" ? range.getBoundingClientRect() : undefined;
    }
    if (!rect || rect.width === 0) continue;
    start = Math.min(start, rect.left);
    end = Math.max(end, rect.right);
  }
  const inner = end > start ? end - start : 0;
  const style = getComputedStyle(cell);
  const pad = (parseFloat(style.paddingInlineStart) || 0) + (parseFloat(style.paddingInlineEnd) || 0);
  return inner + pad;
}

function headerCells(table: HTMLTableElement | undefined): HTMLTableCellElement[] {
  const row = table?.tHead?.rows[0];
  return row ? Array.from(row.cells) : [];
}

/**
 * Widths of the columns of one table. `columns` are the resizable columns in order (the last
 * takes the remaining width once widths are stored); `extra` is the width of fixed columns
 * outside them (a selection or an actions column).
 */
export function createResizer(options: {
  widths: ColumnWidths;
  columns: () => readonly ResizableColumn[];
  table: () => HTMLTableElement | undefined;
  extra?: () => number;
}): Resizer {
  const { widths } = options;
  const isLast = (id: string) => {
    const list = options.columns();
    return list[list.length - 1]?.id === id;
  };
  const column = (id: string) => options.columns().find((c) => c.id === id);
  const header = (id: string) => headerCells(options.table()).find((th) => th.dataset.col === id);
  const fixedWidth = (c: ResizableColumn) => widths.get(c.id) ?? c.width ?? DEFAULT_WIDTH;

  const colWidth = (id: string) => {
    const c = column(id);
    if (!c) return undefined;
    if (!widths.custom()) return c.width;
    return isLast(id) ? undefined : fixedWidth(c);
  };

  /** Fixes every column but the last at its laid-out width, where none is stored yet. */
  const freeze = () => {
    const patch: Record<string, number> = {};
    const list = options.columns();
    list.forEach((c, i) => {
      if (i === list.length - 1 || widths.get(c.id) !== undefined) return;
      patch[c.id] = laidOut(header(c.id)) || c.width || DEFAULT_WIDTH;
    });
    if (Object.keys(patch).length > 0) widths.update(patch);
  };

  const current = (id: string) => laidOut(header(id)) || widths.get(id) || column(id)?.width || DEFAULT_WIDTH;

  return {
    enabled: () => !widths.narrow(),
    colWidth,
    tableWidth() {
      if (!widths.custom()) return undefined;
      const list = options.columns();
      const sum = list.reduce(
        (total, c, i) => total + (i === list.length - 1 ? (widths.get(c.id) ?? c.width ?? MIN_WIDTH) : fixedWidth(c)),
        options.extra?.() ?? 0,
      );
      return `max(100%, ${sum}px)`;
    },
    width: (id) => widths.get(id) ?? column(id)?.width ?? DEFAULT_WIDTH,
    start(id) {
      const width = current(id);
      freeze();
      return width;
    },
    resize: (id, width) => widths.update({ [id]: clampWidth(width) }),
    commit: () => widths.commit(),
    fit(id) {
      const table = options.table();
      if (!table) return;
      const cells = Array.from(table.querySelectorAll<HTMLElement>("th[data-col], td[data-col]")).filter(
        (cell) => cell.dataset.col === id,
      );
      freeze();
      widths.update({ [id]: fitWidth(cells.map(contentWidth)) });
      widths.commit();
    },
  };
}

/** How long two taps (or clicks) may be apart to count as a double tap, in milliseconds. */
const DOUBLE_TAP_MS = 400;
/** A pointer that moves less than this many pixels has tapped, not dragged. */
const TAP_SLOP = 4;

export function ColumnResize(props: {
  resizer: Resizer;
  column: string;
  /** The accessible name ("Resize column Name"). */
  label: string;
  /** Whether the handle is in the tab order (default true). */
  tabbable?: boolean;
  /** Enter or Escape: where the focus goes back to. */
  onEnd?: () => void;
}) {
  let el!: HTMLDivElement;
  const [dragging, setDragging] = createSignal(false);
  let drag: { pointer: number; start: number; x: number; rtl: boolean; moved: boolean } | null = null;
  let lastTap = 0;

  const stopDrag = () => {
    drag = null;
    setDragging(false);
    document.documentElement.classList.remove("col-resizing");
  };
  onCleanup(stopDrag);

  const onPointerDown = (e: PointerEvent) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    el.focus({ preventScroll: true });
    drag = { pointer: e.pointerId, start: props.resizer.start(props.column), x: e.clientX, rtl: isRtl(el), moved: false };
    try {
      el.setPointerCapture(e.pointerId);
    } catch {
      // A synthetic pointer (under test) cannot be captured; moves still arrive on the handle.
    }
    setDragging(true);
    document.documentElement.classList.add("col-resizing");
  };

  const onPointerMove = (e: PointerEvent) => {
    if (!drag || e.pointerId !== drag.pointer) return;
    if (Math.abs(e.clientX - drag.x) >= TAP_SLOP) drag.moved = true;
    if (drag.moved) props.resizer.resize(props.column, dragWidth(drag.start, drag.x, e.clientX, drag.rtl));
  };

  const onPointerUp = (e: PointerEvent) => {
    if (!drag || e.pointerId !== drag.pointer) return;
    const moved = drag.moved;
    stopDrag();
    if (moved) {
      props.resizer.commit();
      lastTap = 0;
      return;
    }
    const now = e.timeStamp || Date.now();
    if (lastTap > 0 && now - lastTap <= DOUBLE_TAP_MS) {
      lastTap = 0;
      props.resizer.fit(props.column);
    } else lastTap = now;
  };

  const onPointerCancel = () => {
    if (!drag) return;
    const moved = drag.moved;
    stopDrag();
    if (moved) props.resizer.commit();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Tab" || e.ctrlKey || e.metaKey || e.altKey) return;
    e.stopPropagation();
    if (e.key === "Enter" || e.key === "Escape") {
      e.preventDefault();
      props.resizer.commit();
      props.onEnd?.();
      return;
    }
    const next = keyWidth(props.resizer.start(props.column), e.key, e.shiftKey, isRtl(el));
    if (next === null) return;
    e.preventDefault();
    props.resizer.resize(props.column, next);
    props.resizer.commit();
  };

  return (
    <div
      ref={el}
      class="col-resize"
      classList={{ active: dragging() }}
      role="separator"
      aria-orientation="vertical"
      aria-label={props.label}
      aria-valuenow={props.resizer.width(props.column)}
      aria-valuemin={MIN_WIDTH}
      aria-valuemax={MAX_WIDTH}
      tabIndex={props.tabbable === false ? -1 : 0}
      data-testid="col-resize"
      data-resize={props.column}
      on:keydown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerCancel}
      onDblClick={(e) => {
        e.stopPropagation();
        props.resizer.fit(props.column);
      }}
      onClick={(e) => e.stopPropagation()}
    />
  );
}
