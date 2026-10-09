// A small popup menu (row actions, filter chips): anchored below an element, arrow keys
// move between items, Enter or Space runs one, Esc or Tab or a click outside closes it and
// the focus returns to where it came from.
import { createSignal, For, onCleanup, onMount, untrack, type JSX } from "solid-js";
import { Portal } from "solid-js/web";

export interface MenuItem {
  id: string;
  label: string;
  /** Secondary text on the right, for example a consequence or a key. */
  hint?: JSX.Element;
  danger?: boolean;
  disabled?: boolean;
  checked?: boolean;
  run: () => void;
}

export function Menu(props: {
  anchor: HTMLElement;
  label: string;
  items: readonly MenuItem[];
  onClose: () => void;
  testid?: string;
}) {
  let panel!: HTMLDivElement;
  const [active, setActive] = createSignal(untrack(() => Math.max(0, props.items.findIndex((i) => !i.disabled))));
  const rect = untrack(() => props.anchor.getBoundingClientRect());
  const opener = document.activeElement as HTMLElement | null;

  const focusItem = (index: number) => {
    setActive(index);
    panel.querySelectorAll<HTMLElement>("[role^=menuitem]")[index]?.focus();
  };
  const step = (delta: number) => {
    const n = props.items.length;
    if (n === 0) return;
    let i = active();
    for (let k = 0; k < n; k++) {
      i = (i + delta + n) % n;
      if (!props.items[i]?.disabled) break;
    }
    focusItem(i);
  };
  const close = () => props.onClose();
  const run = (item: MenuItem) => {
    if (item.disabled) return;
    close();
    item.run();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    e.stopPropagation();
    if (e.key === "ArrowDown") {
      e.preventDefault();
      step(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      step(-1);
    } else if (e.key === "Home") {
      e.preventDefault();
      focusItem(0);
    } else if (e.key === "End") {
      e.preventDefault();
      focusItem(props.items.length - 1);
    } else if (e.key === "Escape" || e.key === "Tab") {
      e.preventDefault();
      close();
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const item = props.items[active()];
      if (item) run(item);
    }
  };

  const onDocDown = (e: MouseEvent) => {
    if (!panel.contains(e.target as Node) && !props.anchor.contains(e.target as Node)) close();
  };
  onMount(() => {
    document.addEventListener("mousedown", onDocDown);
    queueMicrotask(() => focusItem(active()));
  });
  onCleanup(() => {
    document.removeEventListener("mousedown", onDocDown);
    if (opener && document.contains(opener)) opener.focus();
  });

  return (
    <Portal>
      <div
        ref={panel}
        class="menu-pop"
        role="menu"
        aria-label={props.label}
        data-testid={props.testid ?? "menu"}
        style={{ top: `${rect.bottom + 4}px`, left: `${Math.max(8, rect.right - 240)}px` }}
        onKeyDown={onKeyDown}
      >
        <For each={props.items}>
          {(item, i) => (
            <button
              type="button"
              role={item.checked === undefined ? "menuitem" : "menuitemcheckbox"}
              aria-checked={item.checked}
              classList={{ danger: !!item.danger }}
              tabIndex={i() === active() ? 0 : -1}
              aria-disabled={item.disabled ? "true" : undefined}
              data-item={item.id}
              onMouseEnter={() => setActive(i())}
              onClick={() => run(item)}
            >
              <span>{item.label}</span>
              {item.hint ? <span class="hint">{item.hint}</span> : null}
            </button>
          )}
        </For>
      </div>
    </Portal>
  );
}
