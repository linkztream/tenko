// An inline text editor for a grid cell (design.css `.cell-input`, `.cell-hint`): Enter
// commits, Esc cancels, and a one-line hint below says what the change does ("Updates the
// DNS name as a job"). The edit commits as it is typed: small edits preview inline.
import { createSignal, onMount, Show, untrack } from "solid-js";
import { errorMessage } from "../api/problem";
import { t } from "../i18n";

export function TextEditor(props: {
  value: string;
  /** Accessible name of the field. */
  label: string;
  hint?: string;
  /** Saves the value; a rejected promise keeps the editor open with the message. */
  commit: (value: string) => Promise<void>;
  close: () => void;
  /** Checks the value before saving; returns a message when it is not acceptable. */
  validate?: (value: string) => string | null;
}) {
  let input!: HTMLInputElement;
  const [value, setValue] = createSignal(untrack(() => props.value));
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  onMount(() => {
    input.focus();
    input.select();
  });

  const save = async () => {
    if (busy()) return;
    const next = value().trim();
    if (next === props.value.trim()) {
      props.close();
      return;
    }
    const problem = props.validate?.(next) ?? null;
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    try {
      await props.commit(next);
      props.close();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <>
      <input
        ref={input}
        class="cell-input"
        value={value()}
        aria-label={props.label}
        aria-invalid={error() ? "true" : undefined}
        aria-describedby="cell-hint"
        disabled={busy()}
        spellcheck={false}
        data-testid="cell-editor"
        onInput={(e) => {
          setValue(e.currentTarget.value);
          setError(null);
        }}
        onKeyDown={(e) => {
          e.stopPropagation();
          if (e.key === "Enter") {
            e.preventDefault();
            void save();
          } else if (e.key === "Escape") {
            e.preventDefault();
            props.close();
          }
        }}
        onBlur={() => {
          if (!busy() && !error()) props.close();
        }}
      />
      <Show when={error() ?? props.hint}>
        <span id="cell-hint" class="cell-hint" role={error() ? "alert" : undefined}>
          {error() ?? props.hint}
        </span>
      </Show>
      <Show when={busy()}>
        <span class="sr-only" role="status">
          {t("grid.saving")}
        </span>
      </Show>
    </>
  );
}
