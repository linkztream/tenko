// Shared pieces of the IPAM forms: the dialog frame, labelled fields with their help and
// error line, select lists for the enums, the messages of server field errors and the
// two-step flow every write follows (the form collects and checks the values, then the plan
// dialog previews and applies; Cancel there comes back to the form with its values intact).
import { createMemo, createResource, createSignal, createUniqueId, For, Show, splitProps, type Accessor, type JSX, type Setter } from "solid-js";
import { fetchAll } from "../api/paginate";
import { ApiError } from "../api/problem";
import type { Site, Status, Vlan, WriteResponse } from "../api/types";
import { STATUSES } from "../api/types";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { t, tDynamic } from "../i18n";
import { PlanDialog, useWriteToast, type SendOptions } from "./plan/PlanDialog";
import { statusWord } from "./words";
import "./forms.css";

// ---------------------------------------------------------------------------------
// Messages of server field errors

/** Numeric strings become numbers so plural and number arguments format correctly. */
function messageArgs(params: Record<string, string>): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(params)) out[key] = /^-?\d+(\.\d+)?$/.test(value) ? Number(value) : value;
  return out;
}

/**
 * The translated message of a field error. The arguments are those of the field error and of
 * the problem itself (a field error has none of its own in most answers). When the message
 * cannot be formatted with them, the server's own sentence stands in.
 */
function fieldMessage(error: ApiError, field: { code: string; params?: Readonly<Record<string, string>> | undefined }): string {
  const key = `errors.${field.code}`;
  const text = tDynamic(key, messageArgs({ ...error.params, ...field.params }));
  if (text !== undefined && text !== key) return text;
  return error.detail || t("errors.generic.field");
}

/** The message of the first server error for one of `names` (a field or its members), if any. */
export function serverFieldMessage(error: unknown, ...names: string[]): string | undefined {
  if (!(error instanceof ApiError)) return undefined;
  const found = error.fieldErrors.find((fe) => names.some((n) => fe.field === n || fe.field.startsWith(`${n}[`)));
  return found ? fieldMessage(error, found) : undefined;
}

/** The messages of the server errors of custom values (`custom.<key>`), by field key. */
export function customFieldErrors(error: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!(error instanceof ApiError)) return out;
  for (const fe of error.fieldErrors) {
    if (fe.field.startsWith("custom.")) out[fe.field.slice("custom.".length)] = fieldMessage(error, fe);
  }
  return out;
}

/**
 * Whether the error needs a place of its own above the buttons: it has no field errors, or one
 * of them is about a field this form does not show. `placed` are the field names the form has.
 */
export function needsGeneralError(error: unknown, placed: readonly string[]): boolean {
  if (!error) return false;
  if (!(error instanceof ApiError) || error.fieldErrors.length === 0) return true;
  return error.fieldErrors.some(
    (fe) => !placed.some((p) => fe.field === p || fe.field.startsWith(`${p}.`) || fe.field.startsWith(`${p}[`)),
  );
}

// ---------------------------------------------------------------------------------
// Fields

/** What a control needs to belong to its field: the id of the label and the help line. */
export interface ControlProps {
  id: string;
  "data-testid": string;
  "aria-invalid": "true" | undefined;
  "aria-describedby": string | undefined;
  "aria-required": "true" | undefined;
}

/** The line under a control: its help, or its error with a glyph (never color alone). */
export function FieldNote(props: { id: string; help?: string | undefined; error?: string | undefined }) {
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
      <span class="help bad field-note" id={props.id} role="alert">
        <Icon name="alert" size="xs" />
        {props.error}
      </span>
    </Show>
  );
}

/**
 * A label, one control and the help or error line. The control comes from the render
 * function, which receives the attributes that tie it to the label and the line:
 * `<Field ...>{(c) => <input {...c} />}</Field>`. `name` is the field of the request; the
 * control gets `data-testid="field-<name>"`.
 */
export function Field(props: {
  name: string;
  label: string;
  help?: string | undefined;
  error?: string | undefined;
  required?: boolean | undefined;
  class?: string | undefined;
  children: (control: ControlProps) => JSX.Element;
}) {
  const id = createUniqueId();
  const noteId = `${id}-note`;
  const control: ControlProps = {
    id,
    get "data-testid"() {
      return `field-${props.name}`;
    },
    get "aria-invalid"() {
      return props.error ? "true" : undefined;
    },
    get "aria-describedby"() {
      return props.error || props.help ? noteId : undefined;
    },
    get "aria-required"() {
      return props.required ? "true" : undefined;
    },
  };
  return (
    <div class={props.class ? `field ${props.class}` : "field"}>
      <label for={id} classList={{ required: props.required }}>
        {props.label}
      </label>
      {props.children(control)}
      <FieldNote id={noteId} help={props.help} error={props.error} />
    </div>
  );
}

/** Several fields in a row; they stack on a narrow screen. */
export function FieldRow(props: { children: JSX.Element; three?: boolean }) {
  return <div class={props.three ? "field-row three" : "field-row"}>{props.children}</div>;
}

export interface Option<T extends string = string> {
  value: T;
  label: string;
}

/** A select over a list of options; the control attributes of its `Field` go in as props. */
export function SelectInput<T extends string>(
  props: Partial<ControlProps> & {
    /** The accessible name of a select that has no label of its own. */
    "aria-label"?: string | undefined;
    value: T;
    options: readonly Option<T>[];
    onChange: (value: T) => void;
    disabled?: boolean | undefined;
  },
) {
  const [own, control] = splitProps(props, ["value", "options", "onChange", "disabled"]);
  return (
    <select class="select" {...control} disabled={own.disabled} onChange={(e) => own.onChange(e.currentTarget.value as T)}>
      <For each={own.options}>
        {(o) => (
          <option value={o.value} selected={o.value === own.value}>
            {o.label}
          </option>
        )}
      </For>
    </select>
  );
}

/** The lifecycle statuses as options. */
export function statusOptions(): Option<Status>[] {
  return STATUSES.map((s) => ({ value: s, label: statusWord(s) }));
}

/** The current value of a select must be among its options, or the select would show another one. */
export function withCurrent(options: Option[], value: string, label: (value: string) => string): Option[] {
  return value === "" || options.some((o) => o.value === value) ? options : [...options, { value, label: label(value) }];
}

// ---------------------------------------------------------------------------------
// Lookups for the selects

function lookup<T>(path: "/api/v1/vlans" | "/api/v1/sites"): Accessor<T[]> {
  const [items] = createResource(async () => {
    try {
      return (await fetchAll<T>(path)).items;
    } catch {
      return [];
    }
  });
  return () => (items.error ? [] : (items() ?? []));
}

/** The live VLANs as options, with "none" first: "10 LAN". */
export function useVlanChoices(): Accessor<Option[]> {
  const vlans = lookup<Vlan>("/api/v1/vlans");
  return createMemo(() => [
    { value: "", label: t("ipam.field.none") },
    ...[...vlans()].sort((a, b) => a.vid - b.vid).map((v) => ({ value: v.id, label: `${v.vid} ${v.name}` })),
  ]);
}

/** The live sites as options, with "none" first. */
export function useSiteChoices(): Accessor<Option[]> {
  const sites = lookup<Site>("/api/v1/sites");
  return createMemo(() => [
    { value: "", label: t("ipam.field.none") },
    ...[...sites()].sort((a, b) => a.name.localeCompare(b.name)).map((s) => ({ value: s.id, label: s.name })),
  ]);
}

// ---------------------------------------------------------------------------------
// Comparing values for the changed fields of a patch

/** A setter that also forgets the server error: the person is changing something. */
export function tracked<T>(set: Setter<T>, flow: FlowState): (value: T) => void {
  return (value) => {
    set(() => value);
    flow.clearError();
  };
}

/** The same tags, whatever their order. */
export function sameTags(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const left = [...a].sort();
  const right = [...b].sort();
  return left.every((tag, i) => tag === right[i]);
}

// ---------------------------------------------------------------------------------
// The dialog frame and the write flow

/** A form in a dialog: title, fields, the general error and Cancel with the submit button. */
export function FormDialog(props: {
  name: string;
  title: string;
  submitLabel: string;
  submitDisabled?: boolean | undefined;
  error?: unknown;
  formRef?: ((form: HTMLFormElement) => void) | undefined;
  onSubmit: () => void;
  onClose: () => void;
  children: JSX.Element;
}) {
  return (
    <Dialog label={props.title} onClose={props.onClose} class="dialog form-dialog">
      <form
        ref={(el) => props.formRef?.(el)}
        class="form-frame"
        data-testid={`dialog-${props.name}`}
        novalidate
        onSubmit={(e) => {
          e.preventDefault();
          props.onSubmit();
        }}
      >
        <h2 class="dialog-title">{props.title}</h2>
        <div class="form-fields">{props.children}</div>
        <ErrorNotice error={props.error} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={props.submitDisabled}>
            {props.submitLabel}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** What the fields of a form see of the flow around them. */
export interface FlowState {
  /** Whether the person has tried to submit: only then are the missing values reported. */
  submitted: Accessor<boolean>;
  /** The last error of the server, for the messages under the fields. */
  error: Accessor<unknown>;
  /** Forget the server error: the person is changing something. */
  clearError: () => void;
}

export interface WriteFormProps<T> {
  /** `dialog-<name>` is the test id of the form. */
  name: string;
  title: string;
  submitLabel: string;
  /** Edit forms: nothing to save until something changed. */
  changed?: boolean | undefined;
  /** The field names of the request that the form shows; other server errors get a general note. */
  placed: readonly string[];
  /** Checks the values; false when something is wrong (the fields show what). */
  validate: () => boolean;
  planTitle: () => string;
  planConfirm: string;
  send: (options: SendOptions) => Promise<WriteResponse<T>>;
  describe?: ((preview: WriteResponse<T>) => JSX.Element) | undefined;
  confirmFor?: ((preview: WriteResponse<T>) => string) | undefined;
  /** The toast text after the write. */
  doneTitle: (item: T) => string;
  onDone: (item: T) => void;
  onClose: () => void;
  children: (flow: FlowState) => JSX.Element;
}

/**
 * The form first, then the plan dialog. A refusal of the preview that names fields brings the
 * person back to the form with the messages under those fields.
 */
export function WriteForm<T>(props: WriteFormProps<T>) {
  const writeToast = useWriteToast();
  const [stage, setStage] = createSignal<"form" | "plan">("form");
  const [submitted, setSubmitted] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  let form: HTMLFormElement | undefined;

  const flow: FlowState = { submitted, error, clearError: () => setError(null) };

  const submit = () => {
    setSubmitted(true);
    if (!props.validate()) {
      form?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
    setError(null);
    setStage("plan");
  };

  const send = async (options: SendOptions) => {
    try {
      return await props.send(options);
    } catch (err) {
      setError(err);
      if (err instanceof ApiError && err.fieldErrors.length > 0) setStage("form");
      throw err;
    }
  };

  return (
    <Show
      when={stage() === "plan"}
      fallback={
        <FormDialog
          name={props.name}
          title={props.title}
          submitLabel={props.submitLabel}
          submitDisabled={props.changed === false}
          error={needsGeneralError(error(), props.placed) ? error() : null}
          formRef={(el) => (form = el)}
          onSubmit={submit}
          onClose={props.onClose}
        >
          {props.children(flow)}
        </FormDialog>
      }
    >
      <PlanDialog
        title={props.planTitle()}
        confirmLabel={props.planConfirm}
        send={send}
        describe={props.describe}
        confirmFor={props.confirmFor}
        onDone={(result) => {
          if (result.item) {
            writeToast(props.doneTitle(result.item), result);
            props.onDone(result.item);
          } else {
            props.onClose();
          }
        }}
        onClose={() => setStage("form")}
      />
    </Show>
  );
}
