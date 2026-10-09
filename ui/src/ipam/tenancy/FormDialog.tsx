// A form in a dialog whose submit previews the plan (PlanDialog) before anything changes;
// Cancel in the preview returns to the form with its values. Used by the small forms of the
// tenancy views (VLANs, sites, tenants, VRFs, custom fields).
import { createSignal, Show, type JSX } from "solid-js";
import { Dialog } from "../../components/Dialog";
import { t } from "../../i18n";
import { PlanDialog, useWriteToast, type Send, type WriteLike } from "../plan/PlanDialog";
import "../forms.css";

export function FormDialog<R extends WriteLike>(props: {
  title: string;
  submitLabel: string;
  /** `data-testid` of the form (`dialog-<name>`). */
  testid: string;
  /** Checks the fields and shows their messages; false keeps the form open. */
  validate: () => boolean;
  send: Send<R>;
  /** The toast after the change applied. */
  doneTitle: () => string;
  onDone: (result: R) => void;
  onClose: () => void;
  children: JSX.Element;
}) {
  const writeToast = useWriteToast();
  const [planning, setPlanning] = createSignal(false);
  return (
    <Show
      when={planning()}
      fallback={
        <Dialog label={props.title} onClose={props.onClose} class="dialog form-dialog">
          <form
            class="form form-fields"
            data-testid={props.testid}
            novalidate
            onSubmit={(e) => {
              e.preventDefault();
              if (props.validate()) setPlanning(true);
            }}
          >
            <h2 class="dialog-title">{props.title}</h2>
            {props.children}
            <div class="dialog-actions">
              <button type="button" class="btn ghost" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="form-submit">
                {props.submitLabel}
              </button>
            </div>
          </form>
        </Dialog>
      }
    >
      <PlanDialog
        title={props.title}
        confirmLabel={props.submitLabel}
        send={props.send}
        onClose={() => setPlanning(false)}
        onDone={(r) => {
          writeToast(props.doneTitle(), r);
          props.onDone(r);
        }}
      />
    </Show>
  );
}

/** A labelled input with its message (`field-<id>` test hook). */
export function TextField(props: {
  id: string;
  label: string;
  value: string;
  onInput: (value: string) => void;
  error?: string | undefined;
  mono?: boolean;
  type?: "text" | "number";
  help?: string;
}) {
  return (
    <div class="field">
      <label for={`f-${props.id}`}>{props.label}</label>
      <input
        id={`f-${props.id}`}
        class={props.mono ? "input mono" : "input"}
        type={props.type ?? "text"}
        value={props.value}
        spellcheck={false}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={props.error ? `f-${props.id}-error` : undefined}
        data-testid={`field-${props.id}`}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show when={props.error}>
        <span class="help bad" id={`f-${props.id}-error`}>
          {props.error}
        </span>
      </Show>
      <Show when={props.help && !props.error}>
        <span class="help">{props.help}</span>
      </Show>
    </div>
  );
}
