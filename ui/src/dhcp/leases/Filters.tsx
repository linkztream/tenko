// The filter fields of the lease and history views (WP7.5): a labelled field whose text is
// committed to the URL a moment after the last keystroke (or at once on Enter or when the field
// loses the focus), a menu, and a `datetime-local` field that keeps RFC 3339 in the URL.
import { createEffect, createSignal, on, onCleanup, Show, untrack, type JSX } from "solid-js";
import { toLocalInput, toRfc3339 } from "../../audit/filters";

/** How long a text filter waits after the last keystroke. */
export const FILTER_DELAY_MS = 300;

export function TextFilter(props: {
  id: string;
  label: string;
  value: string;
  placeholder?: string;
  mono?: boolean;
  /** The message of a value the server will not take. */
  problem?: string | undefined;
  onCommit: (value: string) => void;
}) {
  const [draft, setDraft] = createSignal(untrack(() => props.value));
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The URL is the source: a change from outside (a reset, a link) replaces what was typed.
  createEffect(on(() => props.value, (value) => setDraft(value), { defer: true }));
  onCleanup(() => clearTimeout(timer));
  const commit = () => {
    clearTimeout(timer);
    if (draft().trim() !== props.value.trim()) props.onCommit(draft().trim());
  };
  return (
    <div class="field">
      <label for={`dhcp-filter-${props.id}`}>{props.label}</label>
      <input
        id={`dhcp-filter-${props.id}`}
        class={props.mono ? "input mono" : "input"}
        value={draft()}
        placeholder={props.placeholder}
        spellcheck={false}
        autocomplete="off"
        aria-invalid={props.problem ? "true" : undefined}
        aria-describedby={props.problem ? `dhcp-filter-${props.id}-error` : undefined}
        data-testid={`filter-${props.id}`}
        onInput={(e) => {
          setDraft(e.currentTarget.value);
          clearTimeout(timer);
          timer = setTimeout(commit, FILTER_DELAY_MS);
        }}
        onChange={(e) => {
          setDraft(e.currentTarget.value);
          commit();
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit();
        }}
      />
      <Show when={props.problem}>
        <span class="help bad" id={`dhcp-filter-${props.id}-error`} data-testid="field-error" data-field={props.id}>
          {props.problem}
        </span>
      </Show>
    </div>
  );
}

/** A menu filter; its children are the `<option>`s, the first of which is the "any" entry with value "". */
export function SelectFilter(props: { id: string; label: string; onCommit: (value: string) => void; children: JSX.Element }) {
  return (
    <div class="field">
      <label for={`dhcp-filter-${props.id}`}>{props.label}</label>
      <select id={`dhcp-filter-${props.id}`} class="select" data-testid={`filter-${props.id}`} onChange={(e) => props.onCommit(e.currentTarget.value)}>
        {props.children}
      </select>
    </div>
  );
}

/** A time filter: the field shows local time, the URL holds RFC 3339 (UTC). */
export function TimeFilter(props: { id: string; label: string; value: string; onCommit: (value: string) => void }) {
  return (
    <div class="field">
      <label for={`dhcp-filter-${props.id}`}>{props.label}</label>
      <input
        id={`dhcp-filter-${props.id}`}
        type="datetime-local"
        class="input"
        value={toLocalInput(props.value === "" ? undefined : props.value)}
        data-testid={`filter-${props.id}`}
        onChange={(e) => props.onCommit(toRfc3339(e.currentTarget.value) ?? "")}
      />
    </div>
  );
}
