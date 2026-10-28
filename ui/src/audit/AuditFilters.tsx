// The filter bar of the audit log: time range, principal, action, object, outcome and order.
// The values live in the URL (see filters.ts); this component only edits them. Text fields
// apply a value after a short pause once it is usable, and at once on Enter or when the
// field loses focus; a value that cannot be used is explained next to its field and never
// sent to the server.
import { createEffect, createSignal, createUniqueId, For, on, onCleanup, Show, untrack } from "solid-js";
import type { UserInfo } from "../api/types";
import { Segmented } from "../components/Segmented";
import { FilterBar } from "../grid/FilterBar";
import { t } from "../i18n";
import { outcomeWord } from "./cells";
import {
  checkAction,
  checkObject,
  checkPrincipal,
  normalize,
  OUTCOMES,
  toLocalInput,
  toRfc3339,
  type FilterName,
  type FilterProblem,
  type FilterState,
  type FilterValues,
} from "./filters";
import { kindWord, OBJECT_KINDS, SYSTEM_COMPONENTS } from "./model";

export type FilterPatch = Partial<Record<FilterName, string | undefined>>;

const APPLY_DELAY_MS = 350;

interface Suggestion {
  value: string;
  label?: string | undefined;
}

function TextFilter(props: {
  name: "principal" | "action" | "object";
  label: string;
  placeholder: string;
  value: string | undefined;
  check: (text: string) => FilterProblem | undefined;
  /** Turns what was typed into the value to apply, on Enter or when the field loses focus. */
  resolve?: ((text: string) => string | undefined) | undefined;
  suggestions?: readonly Suggestion[] | undefined;
  onCommit: (value: string | undefined) => void;
}) {
  const inputId = createUniqueId();
  const helpId = createUniqueId();
  const listId = createUniqueId();
  let committed = untrack(() => props.value ?? "");
  const [draft, setDraft] = createSignal(committed);
  // Errors are shown once the person is done typing (or when the link already carried the value).
  const [attention, setAttention] = createSignal(committed !== "");
  let timer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(timer));

  // The URL changed from outside: Back, a link, "Clear filters".
  createEffect(
    on(
      () => props.value ?? "",
      (v) => {
        if (v === committed) return;
        committed = v;
        setDraft(v);
        setAttention(v !== "");
      },
      { defer: true },
    ),
  );

  const apply = (text: string, final: boolean) => {
    let value = normalize(text);
    if (value !== "" && props.check(value)) {
      const resolved = final ? props.resolve?.(value) : undefined;
      if (!resolved) return;
      value = resolved;
    }
    // What was typed is shown as the filter reads it: trimmed, in lower case, a name resolved.
    if (final) setDraft(value);
    if (value === committed) return;
    committed = value;
    props.onCommit(value === "" ? undefined : value);
  };

  const settle = () => {
    clearTimeout(timer);
    setAttention(true);
    apply(draft(), true);
  };

  const problem = () => {
    const text = normalize(draft());
    if (!attention() || text === "") return undefined;
    const key = props.check(text);
    return key && !props.resolve?.(text) ? key : undefined;
  };

  return (
    <div class="afield">
      <label for={inputId}>{props.label}</label>
      <input
        id={inputId}
        class="input mono"
        classList={{ bad: problem() !== undefined }}
        type="text"
        value={draft()}
        placeholder={props.placeholder}
        spellcheck={false}
        autocomplete="off"
        list={props.suggestions ? listId : undefined}
        aria-invalid={problem() ? "true" : undefined}
        aria-describedby={problem() ? helpId : undefined}
        data-testid={`audit-filter-${props.name}`}
        onInput={(e) => {
          setDraft(e.currentTarget.value);
          setAttention(false);
          clearTimeout(timer);
          timer = setTimeout(() => apply(draft(), false), APPLY_DELAY_MS);
        }}
        onBlur={settle}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            settle();
          }
        }}
      />
      <Show when={problem()}>{(key) => <span id={helpId} class="help bad">{t(key())}</span>}</Show>
      <Show when={props.suggestions}>
        {(list) => (
          <datalist id={listId}>
            <For each={list()}>{(s) => <option value={s.value} label={s.label} />}</For>
          </datalist>
        )}
      </Show>
    </div>
  );
}

function TimeFilter(props: {
  name: "from" | "to";
  label: string;
  value: string | undefined;
  problem: string | undefined;
  onCommit: (value: string | undefined) => void;
}) {
  const inputId = createUniqueId();
  const helpId = createUniqueId();
  return (
    <div class="afield">
      <label for={inputId}>{props.label}</label>
      <input
        id={inputId}
        class="input"
        type="datetime-local"
        value={toLocalInput(props.value)}
        aria-invalid={props.problem ? "true" : undefined}
        aria-describedby={props.problem ? helpId : undefined}
        data-testid={`audit-filter-${props.name}`}
        onChange={(e) => props.onCommit(toRfc3339(e.currentTarget.value))}
      />
      <Show when={props.problem}>{(text) => <span id={helpId} class="help bad">{text()}</span>}</Show>
    </div>
  );
}

export function AuditFilters(props: {
  values: FilterValues;
  state: FilterState;
  users: readonly UserInfo[];
  onChange: (patch: FilterPatch, replace?: boolean) => void;
}) {
  const outcomeId = createUniqueId();
  const any = () => Object.keys(props.values).length > 0;

  const principals = (): Suggestion[] => [
    ...props.users.map((u) => ({ value: `user:${u.id}`, label: u.display_name || u.name })),
    ...SYSTEM_COMPONENTS.map((component) => ({
      value: `system:${component}`,
      label: t("principal.system", { component }),
    })),
  ];
  const resolveUser = (text: string): string | undefined => {
    const user = props.users.find((u) => u.name.toLowerCase() === text || u.display_name.toLowerCase() === text);
    return user ? `user:${user.id}` : undefined;
  };
  const kinds = (): Suggestion[] => OBJECT_KINDS.map((kind) => ({ value: kind, label: kindWord(kind) }));

  const problemText = (name: FilterName): FilterProblem | undefined => props.state.problems[name];

  return (
    <FilterBar
      class="audit-filters"
      role="group"
      label={t("audit.filters.label")}
      testid="audit-filters"
      actions={
        <Show when={any()}>
          <button
            type="button"
            class="btn sm"
            data-testid="audit-filter-clear"
            onClick={() =>
              props.onChange({
                from: undefined,
                to: undefined,
                principal: undefined,
                action: undefined,
                object: undefined,
                outcome: undefined,
                order: undefined,
              })
            }
          >
            {t("audit.filter.clear")}
          </button>
        </Show>
      }
    >
      <TimeFilter
        name="from"
        label={t("audit.filter.from")}
        value={props.values.from}
        problem={problemText("from") ? t(problemText("from") as FilterProblem) : undefined}
        onCommit={(v) => props.onChange({ from: v })}
      />
      <TimeFilter
        name="to"
        label={t("audit.filter.to")}
        value={props.values.to}
        problem={
          problemText("to")
            ? t(problemText("to") as FilterProblem)
            : props.state.emptyRange
              ? t("audit.filter.range_invalid")
              : undefined
        }
        onCommit={(v) => props.onChange({ to: v })}
      />
      <TextFilter
        name="principal"
        label={t("audit.filter.principal")}
        placeholder={t("audit.filter.principal_placeholder")}
        value={props.values.principal}
        check={checkPrincipal}
        resolve={resolveUser}
        suggestions={principals()}
        onCommit={(v) => props.onChange({ principal: v }, true)}
      />
      <TextFilter
        name="action"
        label={t("audit.filter.action")}
        placeholder={t("audit.filter.action_placeholder")}
        value={props.values.action}
        check={checkAction}
        onCommit={(v) => props.onChange({ action: v }, true)}
      />
      <TextFilter
        name="object"
        label={t("audit.filter.object")}
        placeholder={t("audit.filter.object_placeholder")}
        value={props.values.object}
        check={checkObject}
        suggestions={kinds()}
        onCommit={(v) => props.onChange({ object: v }, true)}
      />
      <div class="afield">
        <label for={outcomeId}>{t("audit.filter.outcome")}</label>
        <select
          id={outcomeId}
          class="select"
          data-testid="audit-filter-outcome"
          onChange={(e) => props.onChange({ outcome: e.currentTarget.value || undefined })}
        >
          <option value="" selected={!props.state.query.outcome}>
            {t("audit.filter.outcome_all")}
          </option>
          <For each={OUTCOMES}>
            {(outcome) => (
              <option value={outcome} selected={props.state.query.outcome === outcome}>
                {outcomeWord(outcome)}
              </option>
            )}
          </For>
        </select>
      </div>
      <div class="afield">
        <span class="label" aria-hidden="true">
          {t("audit.filter.order")}
        </span>
        <span data-testid="audit-filter-order">
          <Segmented
            label={t("audit.filter.order")}
            value={props.state.order}
            options={[
              { value: "desc", label: t("audit.filter.order_desc") },
              { value: "asc", label: t("audit.filter.order_asc") },
            ]}
            onChange={(order) => props.onChange({ order: order === "asc" ? "asc" : undefined })}
          />
        </span>
      </div>
    </FilterBar>
  );
}
