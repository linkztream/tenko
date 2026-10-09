// What is being dragged right now: the objects lifted from a grid (design decision 5:
// dragging onto the prefix tree is the move gesture). The browser's dataTransfer cannot be
// read while dragging over a target, so the payload lives here; a drop target reads it to
// decide whether it accepts the drop and to say why not.
import { createSignal } from "solid-js";

export interface DragItem {
  /** Object kind: `host` or `address`. */
  kind: string;
  id: string;
  /** What the drag ghost and the drop hint show: a host name or an address. */
  label: string;
  /** The address the object has now, when it has one. */
  ip?: string | undefined;
}

const [dragged, setDragged] = createSignal<readonly DragItem[] | null>(null);

/** The objects being dragged, or null outside a drag. */
export { dragged };

export function startDrag(items: readonly DragItem[]): void {
  setDragged(items.length ? items : null);
}

export function endDrag(): void {
  setDragged(null);
}

/** The MIME type the payload is also written under, for drops from another window. */
export const DRAG_MIME = "application/x-tenko-objects";
