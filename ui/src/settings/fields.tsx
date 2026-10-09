// Small form pieces shared by the settings dialogs: help or error text tied to its input,
// and a labelled select.
import { For, Show, type JSX } from "solid-js";
import { ApiError, fieldErrorMessage, isApiError } from "../api/problem";
import { Icon } from "../components/Icon";
import { t } from "../i18n";

/** The line under an input: its help, or its error with a glyph (never color alone). */
export function FieldHelp(props: { id: string; help?: JSX.Element; error?: string | undefined }) {
  return (
    <Show
      when={props.error}
      fallback={
        <Show when={props.help}>
          <span class="help" id={props.id}>
            {props.help}
          </span>
        </Show>
      }
    >
      <span class="help bad field-error" id={props.id}>
        <Icon name="alert" size="xs" />
        {props.error}
      </span>
    </Show>
  );
}

export interface ChoiceOption<T extends string> {
  value: T;
  label: string;
}

/** A select with a visible label. */
export function SelectField<T extends string>(props: {
  id: string;
  label: string;
  value: T;
  options: readonly ChoiceOption<T>[];
  onChange: (value: T) => void;
  help?: JSX.Element;
  disabled?: boolean;
}) {
  const helpId = () => `${props.id}-help`;
  return (
    <div class="field">
      <label for={props.id}>{props.label}</label>
      <select
        id={props.id}
        class="select"
        disabled={props.disabled}
        aria-describedby={props.help ? helpId() : undefined}
        onChange={(e) => props.onChange(e.currentTarget.value as T)}
      >
        <For each={props.options}>
          {(o) => (
            <option value={o.value} selected={o.value === props.value}>
              {o.label}
            </option>
          )}
        </For>
      </select>
      <FieldHelp id={helpId()} help={props.help} />
    </div>
  );
}

/** The messages of the field errors the server reported for one request field. */
export function fieldMessages(err: unknown, field: string): string[] {
  if (!(err instanceof ApiError)) return [];
  return err.fieldErrors.filter((fe) => fe.field === field).map((fe) => fieldErrorMessage(fe));
}

/** After a refused change because someone else changed the same thing: the page has reloaded it. */
export function ReloadedNote(props: { error: unknown }) {
  return (
    <Show when={isApiError(props.error, "sys.store.precondition_failed")}>
      <p class="muted">{t("settings.reloaded")}</p>
    </Show>
  );
}
