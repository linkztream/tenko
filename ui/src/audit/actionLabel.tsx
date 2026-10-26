// The words for the action of an audit record. The code (`ipam.proposal.open`) stays the
// truth and stays visible; a sentence-case label in the language of the UI (`Open a proposal`)
// goes before it when the catalog has one (`audit.action.<code>`, ui/i18n/<language>.d/labels.xlf).
import { Show } from "solid-js";
import type { AuditDraft } from "../api/types";
import { tDynamic } from "../i18n";

/**
 * The arguments of a label: `count` is the number of the objects of the record, and every
 * entry of its context is an argument under its own key.
 */
function labelArgs(draft: Pick<AuditDraft, "objects" | "details">): Record<string, unknown> {
  return { ...draft.details?.context, count: draft.objects?.length ?? 0 };
}

/** The label of the action of a record, or `undefined` for a code the catalog does not know. */
export function auditActionLabel(draft: Pick<AuditDraft, "action" | "objects" | "details">): string | undefined {
  return tDynamic(`audit.action.${draft.action}`, labelArgs(draft));
}

/**
 * The action of a record: the label with the code after it (or below it when `stacked`), in the
 * data font; just the code when the catalog has no label for it.
 */
export function AuditAction(props: { draft: Pick<AuditDraft, "action" | "objects" | "details">; stacked?: boolean }) {
  return (
    <Show when={auditActionLabel(props.draft)} fallback={<span class="mono">{props.draft.action}</span>}>
      {(label) => (
        <span class="audit-action" classList={{ stacked: props.stacked }}>
          <span class="audit-action-label">{label()}</span>{" "}
          <span class="audit-action-code mono muted">{props.draft.action}</span>
        </span>
      )}
    </Show>
  );
}
