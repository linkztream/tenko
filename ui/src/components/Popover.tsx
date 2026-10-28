// A small non-modal layer anchored below the control that opened it: the explanation behind a
// page's info button, the cluster card of the node chip, what a security profile changes. It
// takes the focus when it opens, keeps the page usable behind it, and closes on Esc (the focus
// returns to the control), on a click outside, and when the focus leaves it and its control.
// The control carries `aria-expanded` and `aria-controls` with the popover's `id`.
import { onCleanup, onMount, type JSX } from "solid-js";
import { Portal } from "solid-js/web";
import "./popover.css";

/** The gap between the control and the popover, and the least distance to the window's edge. */
const GAP = 6;
const EDGE = 8;

export function Popover(props: {
  anchor: HTMLElement;
  /** Accessible name. */
  label: string;
  id?: string;
  onClose: () => void;
  testid?: string;
  class?: string;
  /** Which edge of the control the popover lines up with; the start edge by default. */
  align?: "start" | "end";
  children: JSX.Element;
}) {
  let panel!: HTMLDivElement;

  const onDown = (e: MouseEvent) => {
    const target = e.target as Node;
    if (!panel.contains(target) && !props.anchor.contains(target)) props.onClose();
  };
  const place = () => {
    const r = props.anchor.getBoundingClientRect();
    const width = panel.offsetWidth;
    const rtl = getComputedStyle(props.anchor).direction === "rtl";
    const atEnd = (props.align === "end") !== rtl;
    const wanted = atEnd ? r.right - width : r.left;
    const left = Math.max(EDGE, Math.min(wanted, window.innerWidth - width - EDGE));
    panel.style.setProperty("top", `${r.bottom + GAP}px`);
    panel.style.setProperty("left", `${left}px`);
  };
  onMount(() => {
    place();
    document.addEventListener("mousedown", onDown);
    window.addEventListener("resize", place);
    queueMicrotask(() => panel.focus());
  });
  onCleanup(() => {
    document.removeEventListener("mousedown", onDown);
    window.removeEventListener("resize", place);
  });

  return (
    <Portal>
      <div
        ref={panel}
        id={props.id}
        class={`popover${props.class ? ` ${props.class}` : ""}`}
        role="dialog"
        aria-label={props.label}
        tabIndex={-1}
        data-testid={props.testid}
        onKeyDown={(e) => {
          if (e.key !== "Escape") return;
          e.stopPropagation();
          // Read before closing: closing unmounts the owner that hands the control in.
          const anchor = props.anchor;
          props.onClose();
          anchor.focus();
        }}
        onFocusOut={(e) => {
          const next = e.relatedTarget as Node | null;
          if (next && !panel.contains(next) && !props.anchor.contains(next)) props.onClose();
        }}
      >
        {props.children}
      </div>
    </Portal>
  );
}
