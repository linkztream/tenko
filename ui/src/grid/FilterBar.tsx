// The filter bar, one pattern for every list (design.css `.filterbar`, ui-plan section 3): the
// query field ("/" focuses it), the chips and fields the view passes in (the exception chips
// with their counts first), actions of the list, the soft-deleted filter where the list has one,
// the row density and the column chooser (which also resets the column widths, so the grid
// leaves that out of its footer).
//
// The query field filters as the person types (`onInput`), or, with `onSubmit`, applies on Enter
// for a list that reads only when asked (the DNS cache). A list whose filters are fields of
// their own (the audit log) or a form (the reconciliation's host) passes no query field.
import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { DENSITIES, density, setDensity, type Density } from "../app/prefs";
import { Icon } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { formatNumber, t, type MessageKey } from "../i18n";
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
  /** Accessible name of the bar ("Filter addresses"); also the name of the query field. */
  label: string;
  placeholder?: string;
  value?: string;
  /** Filters as the person types. Without it and without `onSubmit` the bar has no query field. */
  onInput?: (value: string) => void;
  /** Applies the field on Enter or with a submit button of the bar: the bar is a form. */
  onSubmit?: () => void;
  /** Why the value of the query field cannot be used, shown beside it. */
  invalid?: string | undefined;
  /** The `data-field` of that message, the name of the value. */
  invalidField?: string;
  /** The `data-testid` of the query field; `filter-input` by default. */
  queryTestid?: string;
  /** The parsed query, to point out terms with a value the field does not allow. */
  parsed?: ParsedQuery;
  /** Chips, fields and toggles of the view. */
  children?: JSX.Element;
  /** Buttons of the list at the end of the bar, before the density. */
  actions?: JSX.Element;
  /** Whether the bar offers the row density (lists in the data grid do). Default true. */
  density?: boolean;
  deleted?: DeletedFilter;
  onDeleted?: (value: DeletedFilter) => void;
  columns?: ColumnState<T>;
  /** Whether "/" focuses this field (the first filter bar of a page). Default true. */
  slashFocus?: boolean;
  /** `toolbar` (default) or `group` for a bar of labelled fields. */
  role?: "toolbar" | "group";
  testid?: string;
  class?: string;
}

export function FilterBar<T>(props: FilterBarProps<T>) {
  let input: HTMLInputElement | undefined;
  const [chooser, setChooser] = createSignal<HTMLElement | null>(null);
  const hasQuery = () => !!props.onInput || !!props.onSubmit;

  createEffect(() => {
    const columns = props.columns;
    if (columns) onCleanup(columns.widths.attachMenu());
  });

  onMount(() => {
    if (props.slashFocus === false) return;
    const onKey = (e: KeyboardEvent) => {
      if (!input || e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented || isTyping(e)) return;
      if (document.querySelector("[aria-modal='true']")) return;
      e.preventDefault();
      input.focus();
      input.select();
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  const field = () => (
    <label class="query" classList={{ bad: !!props.invalid }}>
      <Icon name="search" size="sm" />
      <input
        ref={input}
        value={props.value ?? ""}
        placeholder={props.placeholder}
        aria-label={props.label}
        aria-invalid={props.invalid ? "true" : undefined}
        spellcheck={false}
        autocomplete="off"
        data-testid={props.queryTestid ?? "filter-input"}
        onInput={(e) => props.onInput?.(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape" && props.value && props.onInput) {
            e.preventDefault();
            e.stopPropagation();
            props.onInput("");
          }
        }}
      />
      <span class="kbd">/</span>
    </label>
  );

  const cls = () => `filterbar${props.class ? ` ${props.class}` : ""}`;
  const body = () => (
    <>
      <Show when={hasQuery()}>{field()}</Show>
      <Show when={props.invalid}>
        {(text) => (
          <span class="invalid" role="status" data-testid="field-error" data-field={props.invalidField}>
            {text()}
          </span>
        )}
      </Show>
      {props.children}
      <Show when={props.parsed?.invalid.length}>
        <span class="invalid" role="status">
          <For each={props.parsed?.invalid ?? []}>
            {(term) => <span>{t("grid.filter.invalid", { field: term.field, value: term.value })} </span>}
          </For>
        </span>
      </Show>
      <div class="right">
        {props.actions}
        <Show when={props.onDeleted}>
          <Segmented
            label={t("grid.deleted.label")}
            value={props.deleted ?? "exclude"}
            options={DELETED.map((d) => ({ value: d, label: t(`grid.deleted.${d}`) }))}
            onChange={(v) => props.onDeleted?.(v)}
          />
        </Show>
        <Show when={props.density !== false}>
          <Segmented
            label={t("grid.density.label")}
            value={density()}
            options={DENSITIES.map((d) => ({ value: d, label: t(DENSITY_LABEL[d]) }))}
            onChange={(v) => setDensity(v)}
          />
        </Show>
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
    </>
  );

  // A bar that applies on Enter is a search form: its submit button and Enter in the field both apply.
  return (
    <Show
      when={props.onSubmit}
      fallback={
        <div class={cls()} role={props.role ?? "toolbar"} aria-label={props.label} data-testid={props.testid ?? "filterbar"}>
          {body()}
        </div>
      }
    >
      <form
        class={cls()}
        role="search"
        aria-label={props.label}
        data-testid={props.testid ?? "filterbar"}
        novalidate
        onSubmit={(e) => {
          e.preventDefault();
          props.onSubmit?.();
        }}
      >
        {body()}
      </form>
    </Show>
  );
}

/**
 * A toggle chip of the filter bar ("Show free", "Needs you"). An exception chip carries the
 * count of its rows (`count`), in the tone of the exception it filters.
 */
export function ToggleChip(props: {
  pressed: boolean;
  onToggle: () => void;
  children: JSX.Element;
  testid?: string;
  /** The rows the chip stands for; no count when unknown. */
  count?: number | undefined;
  /** More rows than `count` exist (a list read page by page). */
  more?: boolean;
  tone?: "conflict" | "proposal" | "discrepancy";
}) {
  return (
    <button
      type="button"
      class={props.tone ? `chip ${props.tone}` : "chip"}
      aria-pressed={props.pressed}
      data-testid={props.testid}
      onClick={() => props.onToggle()}
    >
      {props.children}
      <Show when={props.count !== undefined}>
        <span class="n" data-testid="chip-count">
          {props.more ? t("grid.filter.count_more", { count: formatNumber(props.count ?? 0) }) : formatNumber(props.count ?? 0)}
        </span>
      </Show>
    </button>
  );
}
