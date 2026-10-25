// The filter bar above a grid (design.css `.filterbar`): a query field that accepts
// `field:value` terms ("/" focuses it), dimension chips the view passes in, the soft-deleted
// filter where the list has one, the row density and the column chooser (which also resets
// the column widths, so the grid leaves that out of its footer).
import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { DENSITIES, density, setDensity, type Density } from "../app/prefs";
import { Icon } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { t, type MessageKey } from "../i18n";
import { isTyping } from "../shell/keyboard";
import { ColumnChooser } from "./ColumnChooser";
import type { ColumnState } from "./prefs";
import type { ParsedQuery } from "./query";

export type DeletedFilter = "exclude" | "include" | "only";
const DELETED: readonly DeletedFilter[] = ["exclude", "include", "only"];

const DENSITY_LABEL: Record<Density, MessageKey> = {
  dense: "grid.density.dense",
  compact: "grid.density.compact",
  comfortable: "grid.density.comfortable",
};

export interface FilterBarProps<T> {
  /** Accessible name of the bar ("Filter addresses"). */
  label: string;
  placeholder: string;
  value: string;
  onInput: (value: string) => void;
  /** The parsed query, to point out terms with a value the field does not allow. */
  parsed?: ParsedQuery;
  /** Chips and toggles of the view. */
  children?: JSX.Element;
  deleted?: DeletedFilter;
  onDeleted?: (value: DeletedFilter) => void;
  columns?: ColumnState<T>;
  /** Whether "/" focuses this field (the first filter bar of a page). Default true. */
  slashFocus?: boolean;
  testid?: string;
}

export function FilterBar<T>(props: FilterBarProps<T>) {
  let input!: HTMLInputElement;
  const [chooser, setChooser] = createSignal<HTMLElement | null>(null);

  createEffect(() => {
    const columns = props.columns;
    if (columns) onCleanup(columns.widths.attachMenu());
  });

  onMount(() => {
    if (props.slashFocus === false) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented || isTyping(e)) return;
      if (document.querySelector("[aria-modal='true']")) return;
      e.preventDefault();
      input.focus();
      input.select();
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  return (
    <div class="filterbar" role="toolbar" aria-label={props.label} data-testid={props.testid ?? "filterbar"}>
      <label class="query">
        <Icon name="search" size="sm" />
        <input
          ref={input}
          value={props.value}
          placeholder={props.placeholder}
          aria-label={props.label}
          spellcheck={false}
          autocomplete="off"
          data-testid="filter-input"
          onInput={(e) => props.onInput(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape" && props.value) {
              e.preventDefault();
              e.stopPropagation();
              props.onInput("");
            }
          }}
        />
        <span class="kbd">/</span>
      </label>
      {props.children}
      <Show when={props.parsed?.invalid.length}>
        <span class="invalid" role="status">
          <For each={props.parsed?.invalid ?? []}>
            {(term) => <span>{t("grid.filter.invalid", { field: term.field, value: term.value })} </span>}
          </For>
        </span>
      </Show>
      <div class="right">
        <Show when={props.onDeleted}>
          <Segmented
            label={t("grid.deleted.label")}
            value={props.deleted ?? "exclude"}
            options={DELETED.map((d) => ({ value: d, label: t(`grid.deleted.${d}`) }))}
            onChange={(v) => props.onDeleted?.(v)}
          />
        </Show>
        <Segmented
          label={t("grid.density.label")}
          value={density()}
          options={DENSITIES.map((d) => ({ value: d, label: t(DENSITY_LABEL[d]) }))}
          onChange={(v) => setDensity(v)}
        />
        <Show when={props.columns}>
          <button
            type="button"
            class="icon-btn"
            aria-label={t("grid.columns.button")}
            title={t("grid.columns.button")}
            aria-expanded={chooser() !== null}
            data-testid="column-chooser"
            onClick={(e) => {
              const el = e.currentTarget;
              setChooser((cur) => (cur ? null : el));
            }}
          >
            <Icon name="columns" />
          </button>
        </Show>
      </div>
      <Show when={chooser() && props.columns}>
        <ColumnChooser anchor={chooser() as HTMLElement} state={props.columns as ColumnState<T>} onClose={() => setChooser(null)} />
      </Show>
    </div>
  );
}

/** A toggle chip of the filter bar ("Show free", "Locked"). */
export function ToggleChip(props: { pressed: boolean; onToggle: () => void; children: JSX.Element; testid?: string }) {
  return (
    <button
      type="button"
      class="chip"
      aria-pressed={props.pressed}
      data-testid={props.testid}
      onClick={() => props.onToggle()}
    >
      {props.children}
    </button>
  );
}
