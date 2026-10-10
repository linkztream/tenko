// Small pieces of the secrets list and detail: the tags, the dash for a missing value, the
// last reveal and the buttons of a secret.
import { For, Show } from "solid-js";
import { formatDateTime, formatRelative, t } from "../i18n";
import type { OperatorSecret } from "./api";

/** The tags of a secret, one chip each; "None" when it has none. */
export function TagList(props: { tags: readonly string[] }) {
  return (
    <Show when={props.tags.length > 0} fallback={<span class="muted">{t("common.none")}</span>}>
      <span class="tag-list">
        <For each={props.tags}>{(tag) => <span class="tag mono">{tag}</span>}</For>
      </span>
    </Show>
  );
}

/** A dash for a value the secret does not have; screen readers hear `label`. */
export function Dash(props: { label: string }) {
  return (
    <span class="muted">
      <span aria-hidden="true">{"–"}</span>
      <span class="sr-only">{props.label}</span>
    </span>
  );
}

/** "alex, 5 minutes ago", or "Never"; the exact time is the tooltip. */
export function LastReveal(props: { secret: OperatorSecret }) {
  return (
    <Show when={props.secret.last_revealed} fallback={t("common.never")}>
      {(reveal) => (
        <span title={formatDateTime(reveal().at)} data-testid="secret-last-reveal">
          {reveal().user_name
            ? t("secrets.revealed_by", { user: reveal().user_name ?? "", when: formatRelative(reveal().at) })
            : formatRelative(reveal().at)}
        </span>
      )}
    </Show>
  );
}

/** What a person may do with a secret: reveal it and, as an administrator, change or delete it. */
export function SecretActions(props: {
  secret: OperatorSecret;
  canWrite: boolean;
  /** The delete button waits while the references are being read. */
  checking: boolean;
  /** The detail uses the red delete button; the list keeps its rows calm. */
  danger?: boolean;
  onReveal: (secret: OperatorSecret) => void;
  onEdit: (secret: OperatorSecret) => void;
  onReplace: (secret: OperatorSecret) => void;
  onDelete: (secret: OperatorSecret) => void;
}) {
  const name = () => props.secret.name;
  return (
    <div class="row-actions">
      <button
        type="button"
        class="btn sm"
        data-testid="secret-reveal"
        aria-label={t("secrets.action.reveal_named", { name: name() })}
        onClick={() => props.onReveal(props.secret)}
      >
        {t("secrets.action.reveal")}
      </button>
      <Show when={props.canWrite}>
        <button
          type="button"
          class="btn sm"
          data-testid="secret-edit"
          aria-label={t("secrets.action.edit_named", { name: name() })}
          onClick={() => props.onEdit(props.secret)}
        >
          {t("secrets.action.edit")}
        </button>
        <button
          type="button"
          class="btn sm"
          data-testid="secret-replace"
          aria-label={t("secrets.action.replace_named", { name: name() })}
          onClick={() => props.onReplace(props.secret)}
        >
          {t("secrets.action.replace")}
        </button>
        <button
          type="button"
          class={props.danger ? "btn sm danger" : "btn sm"}
          data-testid="secret-delete"
          aria-label={t("secrets.action.delete_named", { name: name() })}
          disabled={props.checking}
          onClick={() => props.onDelete(props.secret)}
        >
          {t("secrets.action.delete")}
        </button>
      </Show>
    </div>
  );
}
