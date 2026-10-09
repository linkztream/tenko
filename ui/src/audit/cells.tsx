// Cells of the audit log, shared by the list and the record page: the outcome as glyph and
// word, the objects of a record with links, and a value that may be missing.
import { A } from "@solidjs/router";
import { For, Show, type JSX } from "solid-js";
import type { AuditOutcome, AuditRecord } from "../api/types";
import { Icon, type IconName } from "../components/Icon";
import { t } from "../i18n";
import { kindWord } from "./model";
import { objectViews } from "./objects";

const OUTCOME_ICON: Record<AuditOutcome["kind"], IconName> = {
  success: "check",
  denied: "lock",
  failed: "alert",
};

/** The outcome as a word. */
export function outcomeWord(kind: AuditOutcome["kind"]): string {
  switch (kind) {
    case "success":
      return t("audit.outcome.success");
    case "denied":
      return t("audit.outcome.denied");
    case "failed":
      return t("audit.outcome.failed");
  }
}

/** The stable error code of a failed outcome. */
export function failedCode(outcome: AuditOutcome): string | undefined {
  return outcome.kind === "failed" ? outcome.code : undefined;
}

/** A dash for "none"; screen readers get the words instead of the dash. */
export function Dash() {
  return (
    <span class="muted">
      <span aria-hidden="true">–</span>
      <span class="sr-only">{t("audit.record.not_set")}</span>
    </span>
  );
}

/** A value that may be missing, in the data font when it is an identifier. */
export function Maybe(props: { value: string | null | undefined; mono?: boolean; title?: string }): JSX.Element {
  return (
    <Show when={props.value} fallback={<Dash />}>
      {(value) => (
        <span classList={{ mono: props.mono ?? false }} title={props.title}>
          {value()}
        </span>
      )}
    </Show>
  );
}

/** The outcome of a record: glyph and word, never color alone. A failure also shows its stable error code. */
export function OutcomeBadge(props: { record: Pick<AuditRecord, "draft"> }) {
  const outcome = () => props.record.draft.outcome;
  return (
    <span class={`outcome ${outcome().kind}`} data-outcome={outcome().kind}>
      <Icon name={OUTCOME_ICON[outcome().kind]} size="xs" />
      <span>{outcomeWord(outcome().kind)}</span>
      <Show when={failedCode(outcome())}>
        {(code) => (
          <span class="outcome-code mono">{code()}</span>
        )}
      </Show>
    </span>
  );
}

/** The objects of a record: kind and label, as a link where the UI has a page for it. */
export function ObjectList(props: { record: Pick<AuditRecord, "draft"> }) {
  const views = () => objectViews(props.record);
  return (
    <Show when={views().length > 0} fallback={<Dash />}>
      <span class="objects">
        <For each={views()}>
          {(view) => (
            <span class="object" data-kind={view.ref.kind}>
              <span class="object-kind">{kindWord(view.ref.kind)}</span>
              <Show
                when={view.href}
                fallback={
                  <span class="mono" title={view.ref.id}>
                    {view.text}
                  </span>
                }
              >
                {(href) => (
                  <A class="mono" href={href()} tabIndex={-1} title={view.ref.id}>
                    {view.text}
                  </A>
                )}
              </Show>
            </span>
          )}
        </For>
      </span>
    </Show>
  );
}
