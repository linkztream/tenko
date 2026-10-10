// Small pieces the dialogs of the secrets page share: the line under an input and the note
// for a change that lost against someone else's.
import { Show, type JSX } from "solid-js";
import { errorMessage, isApiError } from "../api/problem";
import { Icon } from "../components/Icon";
import { Notice } from "../components/Notice";
import { t } from "../i18n";

/** The line under an input: its error with a glyph (never color alone), else its help. */
export function FieldNote(props: { id: string; help?: JSX.Element; error?: string | undefined }) {
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
      <span class="help bad field-error" id={props.id} data-testid="field-error">
        <Icon name="alert" size="xs" />
        {props.error}
      </span>
    </Show>
  );
}

/**
 * Shown when the server refused a change because the secret changed meanwhile (409
 * `vault.secret.conflict`): the words of the refusal and the button that loads the latest.
 */
export function ConflictNotice(props: { error: unknown; busy: boolean; onReload: () => void }) {
  return (
    <Show when={isApiError(props.error, "vault.secret.conflict")}>
      <Notice kind="bad" role="alert" testid="secret-conflict">
        <span class="conflict-text">{errorMessage(props.error)}</span>{" "}
        <button type="button" class="btn sm" data-testid="secret-reload" disabled={props.busy} onClick={() => props.onReload()}>
          <Icon name="refresh" size="sm" /> {t("secrets.form.reload")}
        </button>
      </Notice>
    </Show>
  );
}
