// Column visibility and order (the column icon of the filter bar). Each column has a check
// box and two buttons that move it one place; the choice is remembered per grid. The foot
// resets the order and visibility, and apart from them the widths the user set.
import { For, onCleanup, onMount, untrack } from "solid-js";
import { Portal } from "solid-js/web";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import type { ColumnState } from "./prefs";

export function ColumnChooser<T>(props: { anchor: HTMLElement; state: ColumnState<T>; onClose: () => void }) {
  let panel!: HTMLDivElement;
  const rect = untrack(() => props.anchor.getBoundingClientRect());

  const onDocDown = (e: MouseEvent) => {
    if (!panel.contains(e.target as Node) && !props.anchor.contains(e.target as Node)) props.onClose();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      props.onClose();
      props.anchor.focus();
    }
  };
  onMount(() => {
    document.addEventListener("mousedown", onDocDown);
    queueMicrotask(() => panel.querySelector<HTMLElement>("input, button")?.focus());
  });
  onCleanup(() => document.removeEventListener("mousedown", onDocDown));

  return (
    <Portal>
      <div
        ref={panel}
        class="colchooser"
        role="dialog"
        aria-label={t("grid.columns.title")}
        data-testid="column-chooser-panel"
        style={{ top: `${rect.bottom + 4}px`, left: `${Math.max(8, rect.right - 280)}px` }}
        onKeyDown={onKey}
      >
        <h3>{t("grid.columns.title")}</h3>
        <ul>
          <For each={props.state.all()}>
            {(column, i) => (
              <li data-col={column.id}>
                <label>
                  <input
                    type="checkbox"
                    class="cb"
                    checked={column.fixed || !props.state.isHidden(column.id)}
                    disabled={column.fixed}
                    onChange={(e) => props.state.setHidden(column.id, !e.currentTarget.checked)}
                  />
                  <span>{column.header()}</span>
                </label>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("grid.columns.move_up", { column: column.header() })}
                  disabled={i() === 0}
                  onClick={() => props.state.move(column.id, -1)}
                >
                  <Icon name="chev-u" size="sm" />
                </button>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("grid.columns.move_down", { column: column.header() })}
                  disabled={i() === props.state.all().length - 1}
                  onClick={() => props.state.move(column.id, 1)}
                >
                  <Icon name="chev-d" size="sm" />
                </button>
              </li>
            )}
          </For>
        </ul>
        <div class="foot">
          <button type="button" class="btn sm ghost" onClick={() => props.state.reset()}>
            {t("grid.columns.reset")}
          </button>
          <button
            type="button"
            class="btn sm ghost"
            data-testid="reset-column-widths"
            disabled={!props.state.widths.custom()}
            onClick={() => props.state.widths.reset()}
          >
            {t("grid.resize.reset")}
          </button>
        </div>
      </div>
    </Portal>
  );
}
