// A modal layer over a scrim: the command palette, the keyboard sheet and confirmation
// dialogs. Focus moves into it, stays inside while it is open (Tab wraps), returns to the
// element that opened it, and Esc or a click on the scrim closes it.
import { onCleanup, onMount, type JSX } from "solid-js";
import { Portal } from "solid-js/web";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface DialogProps {
  /** Accessible name. */
  label: string;
  onClose: () => void;
  /** Class of the panel inside the scrim: `palette`, `sheet` or `dialog`. */
  class?: string;
  /** The `data-testid` of the panel (`dialog-<name>`, see ui/README.md). */
  testid?: string;
  /** Element to focus first; otherwise the first focusable element. */
  initialFocus?: () => HTMLElement | undefined;
  children: JSX.Element;
}

export function Dialog(props: DialogProps) {
  let panel!: HTMLDivElement;
  const opener = document.activeElement as HTMLElement | null;

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      props.onClose();
      return;
    }
    if (e.key !== "Tab") return;
    const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.hidden);
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last?.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first?.focus();
    }
  };

  onMount(() => {
    const target = props.initialFocus?.() ?? panel.querySelector<HTMLElement>(FOCUSABLE) ?? panel;
    queueMicrotask(() => target.focus());
  });
  onCleanup(() => {
    if (opener && document.contains(opener)) opener.focus();
  });

  return (
    <Portal>
      <div
        class="overlay open"
        onMouseDown={(e) => {
          if (e.target === e.currentTarget) props.onClose();
        }}
      >
        <div
          ref={panel}
          class={props.class ?? "dialog"}
          role="dialog"
          aria-modal="true"
          aria-label={props.label}
          data-testid={props.testid}
          tabIndex={-1}
          onKeyDown={onKeyDown}
        >
          {props.children}
        </div>
      </div>
    </Portal>
  );
}

/** A confirmation dialog whose confirm button names the action ("Revoke 3 sessions"). */
export function ConfirmDialog(props: {
  title: string;
  /** The `data-testid` of the panel; `dialog-confirm` by default. */
  testid?: string;
  body?: JSX.Element;
  confirmLabel: string;
  cancelLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  let confirm!: HTMLButtonElement;
  return (
    <Dialog
      label={props.title}
      onClose={props.onClose}
      class="dialog"
      initialFocus={() => confirm}
      testid={props.testid ?? "dialog-confirm"}
    >
      <h2 class="dialog-title">{props.title}</h2>
      <div class="dialog-body">{props.body}</div>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" onClick={() => props.onClose()} data-testid="confirm-cancel">
          {props.cancelLabel}
        </button>
        <button
          ref={confirm}
          type="button"
          class={props.danger ? "btn danger" : "btn primary"}
          disabled={props.busy}
          onClick={() => props.onConfirm()}
          data-testid="confirm-ok"
        >
          {props.confirmLabel}
        </button>
      </div>
    </Dialog>
  );
}
