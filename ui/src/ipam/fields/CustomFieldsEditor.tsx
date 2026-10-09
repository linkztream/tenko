// Tags and custom values of IPAM objects: the inputs of the forms and the read-only list of
// the detail pages. Custom fields are defined once (GET /custom-fields) and apply to some
// kinds of object; the editor draws one input per definition, by its value type (IPAM-08).
import { createEffect, createMemo, createResource, createSignal, For, Show, untrack, type Accessor, type JSX } from "solid-js";
import { api } from "../../api/client";
import type { CustomFieldDef, CustomValue, ObjectKind } from "../../api/types";
import { Icon } from "../../components/Icon";
import { formatDate, formatNumber, t } from "../../i18n";
import { Field, SelectInput, type ControlProps } from "../formKit";
import { customKindWord } from "../words";

// ---------------------------------------------------------------------------------
// The definitions

/**
 * The custom field definitions that apply to a kind of object, by key. Empty until the list
 * has loaded and when it cannot be read.
 */
export function useCustomFields(kind: () => string): Accessor<CustomFieldDef[]> {
  const [all] = createResource(async () => {
    try {
      return (await api.get("/api/v1/custom-fields")).items;
    } catch {
      return [];
    }
  });
  const defs = createMemo(() =>
    (all.error ? [] : (all() ?? []))
      .filter((d) => d.applies_to.includes(kind() as ObjectKind))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
  );
  return defs;
}

// ---------------------------------------------------------------------------------
// Values

/** What a value says in an input. */
function textOf(value: CustomValue | undefined): string {
  return value === undefined || value.type === "boolean" ? "" : String(value.value);
}

function isInteger(text: string): boolean {
  return /^[+-]?\d{1,15}$/.test(text.trim());
}

function parseUrl(text: string): URL | null {
  try {
    return new URL(text.trim());
  } catch {
    return null;
  }
}

/** A link only for web addresses: anything else (javascript:, data:) is shown as text. */
function webUrl(text: string): string | null {
  const url = parseUrl(text);
  return url && (url.protocol === "https:" || url.protocol === "http:") ? url.href : null;
}

/**
 * The custom members of a patch: the values that are new or changed, and `null` for a value
 * that was removed. Undefined when nothing changed.
 */
export function customPatch(
  before: Record<string, CustomValue>,
  after: Record<string, CustomValue>,
): Record<string, CustomValue | null> | undefined {
  const out: Record<string, CustomValue | null> = {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const now = after[key];
    const was = before[key];
    if (now === undefined) {
      if (was !== undefined) out[key] = null;
    } else if (was === undefined || was.type !== now.type || was.value !== now.value) {
      out[key] = now;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// ---------------------------------------------------------------------------------
// The editor

interface Problem {
  message: string;
  /** Only reported once the person has tried to submit (a missing value). */
  late: boolean;
}

export function CustomFieldsEditor(props: {
  kind: string;
  values: Record<string, CustomValue>;
  onChange: (values: Record<string, CustomValue>) => void;
  /** Messages by field key, for example from the server. */
  errors?: Record<string, string> | undefined;
  /** Report the missing required values too. */
  showRequired?: boolean | undefined;
  /** Called with the problems that stop a submit, by field key. */
  onProblems?: ((problems: Record<string, string>) => void) | undefined;
}) {
  const defs = useCustomFields(() => props.kind);
  // What the person typed, where it may not be a value yet ("1.", a half-typed address).
  const [typed, setTyped] = createSignal<Record<string, string>>({});
  const textFor = (def: CustomFieldDef) => typed()[def.key] ?? textOf(props.values[def.key]);

  const store = (key: string, value: CustomValue | undefined) => {
    const next = { ...props.values };
    if (value === undefined) delete next[key];
    else next[key] = value;
    props.onChange(next);
  };

  const edit = (def: CustomFieldDef, text: string) => {
    setTyped({ ...typed(), [def.key]: text });
    const trimmed = text.trim();
    if (trimmed === "") return store(def.key, undefined);
    switch (def.kind.type) {
      case "integer":
        return store(def.key, isInteger(trimmed) ? { type: "integer", value: Number(trimmed) } : undefined);
      case "url":
        return store(def.key, parseUrl(trimmed) ? { type: "url", value: trimmed } : undefined);
      case "date":
        return store(def.key, { type: "date", value: trimmed });
      case "select":
        return store(def.key, { type: "select", value: trimmed });
      case "text":
        return store(def.key, { type: "text", value: trimmed });
      case "boolean":
        return;
    }
  };

  const problemOf = (def: CustomFieldDef): Problem | undefined => {
    const text = textFor(def).trim();
    const value = props.values[def.key];
    switch (def.kind.type) {
      case "integer":
        if (text !== "" && !isInteger(text)) return { message: t("ipam.field.integer_invalid"), late: false };
        break;
      case "url":
        if (text !== "" && !parseUrl(text)) return { message: t("ipam.field.url_invalid"), late: false };
        break;
      case "select":
        if (value !== undefined && !def.kind.options.includes(String(value.value))) {
          return { message: t("ipam.field.option_invalid"), late: false };
        }
        break;
      default:
        break;
    }
    if (def.required && value === undefined) return { message: t("ipam.field.required"), late: true };
    return undefined;
  };

  const problems = createMemo(() => {
    const out: Record<string, Problem> = {};
    for (const def of defs()) {
      const problem = problemOf(def);
      if (problem) out[def.key] = problem;
    }
    return out;
  });

  createEffect(() => {
    const out: Record<string, string> = {};
    for (const [key, problem] of Object.entries(problems())) out[key] = problem.message;
    props.onProblems?.(out);
  });

  // A required check box is either checked or not: unchecked is a value too.
  createEffect(() => {
    const missing = defs().filter((d) => d.kind.type === "boolean" && d.required && untrack(() => props.values[d.key]) === undefined);
    if (missing.length === 0) return;
    const next = { ...untrack(() => props.values) };
    for (const def of missing) next[def.key] = { type: "boolean", value: false };
    props.onChange(next);
  });

  const messageOf = (def: CustomFieldDef): string | undefined => {
    const own = props.errors?.[def.key];
    if (own) return own;
    const problem = problems()[def.key];
    return problem && (!problem.late || props.showRequired) ? problem.message : undefined;
  };

  const input = (def: CustomFieldDef, control: ControlProps): JSX.Element => {
    const kind = def.kind;
    switch (kind.type) {
      case "boolean":
        return (
          <div class="check-field">
            <input
              type="checkbox"
              class="cb"
              {...control}
              checked={props.values[def.key]?.value === true}
              onChange={(e) => store(def.key, { type: "boolean", value: e.currentTarget.checked })}
            />
            <span class="muted">{t(props.values[def.key]?.value === true ? "common.yes" : "common.no")}</span>
          </div>
        );
      case "select":
        return (
          <SelectInput
            {...control}
            value={textFor(def)}
            options={[
              { value: "", label: def.required ? t("ipam.field.choose") : t("ipam.field.none") },
              ...kind.options.map((o) => ({ value: o, label: o })),
            ]}
            onChange={(v) => edit(def, v)}
          />
        );
      default:
        return (
          <input
            class="input"
            type={kind.type === "integer" ? "number" : kind.type === "text" ? "text" : kind.type}
            step={kind.type === "integer" ? 1 : undefined}
            maxLength={kind.type === "text" ? 1024 : undefined}
            autocomplete="off"
            {...control}
            value={textFor(def)}
            onInput={(e) => edit(def, e.currentTarget.value)}
          />
        );
    }
  };

  return (
    <Show when={defs().length > 0}>
      <fieldset class="field-group" data-testid="custom-fields">
        <legend>{t("ipam.field.custom")}</legend>
        <For each={defs()}>
          {(def) => (
            <Field
              name={`custom-${def.key}`}
              label={def.key}
              help={customKindWord(def.kind.type)}
              error={messageOf(def)}
              required={def.required}
            >
              {(control) => input(def, control)}
            </Field>
          )}
        </For>
      </fieldset>
    </Show>
  );
}

// ---------------------------------------------------------------------------------
// Read only

function valueView(value: CustomValue): JSX.Element {
  switch (value.type) {
    case "boolean":
      return value.value ? t("common.yes") : t("common.no");
    case "integer":
      return formatNumber(value.value);
    case "date":
      return Number.isNaN(Date.parse(value.value)) ? value.value : formatDate(value.value, { dateStyle: "medium", timeZone: "UTC" });
    case "url": {
      const href = webUrl(value.value);
      return href ? (
        <a href={href} target="_blank" rel="noopener noreferrer">
          {value.value}
        </a>
      ) : (
        value.value
      );
    }
    default:
      return value.value;
  }
}

/** The custom values of an object as a list of key and value. Nothing when there are none. */
export function CustomValues(props: { values?: Record<string, CustomValue> | null | undefined }) {
  const entries = () => Object.entries(props.values ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return (
    <Show when={entries().length > 0}>
      <dl class="kv custom-values" data-testid="custom-values">
        <For each={entries()}>
          {([key, value]) => (
            <>
              <dt class="mono">{key}</dt>
              <dd data-key={key}>{valueView(value)}</dd>
            </>
          )}
        </For>
      </dl>
    </Show>
  );
}

// ---------------------------------------------------------------------------------
// Tags

const MAX_TAG = 64;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function validTag(tag: string): boolean {
  const length = Array.from(tag).length;
  return length >= 1 && length <= MAX_TAG && !CONTROL.test(tag);
}

/**
 * Tags typed as text: a comma, Enter or leaving the input makes what was typed into tags
 * (trimmed, once each, 1 to 64 characters). The tags show as chips that can be removed.
 */
export function TagsInput(props: {
  label: string;
  value: readonly string[];
  onChange: (tags: string[]) => void;
  /** The field name of the request, for the test id (`field-<name>`). */
  name?: string | undefined;
  help?: string | undefined;
  error?: string | undefined;
}) {
  const [text, setText] = createSignal("");
  const [problem, setProblem] = createSignal<string | undefined>();
  let input: HTMLInputElement | undefined;

  /** Adds the tags in `parts`; false (and a message) when one of them is not a tag. */
  const add = (parts: readonly string[]): boolean => {
    const tags = parts.map((p) => p.trim()).filter((p) => p !== "");
    if (tags.some((tag) => !validTag(tag))) {
      setProblem(t("ipam.field.tag_invalid", { max: MAX_TAG }));
      return false;
    }
    setProblem(undefined);
    const next = [...props.value];
    for (const tag of tags) if (!next.includes(tag)) next.push(tag);
    if (next.length !== props.value.length) props.onChange(next);
    return true;
  };

  const flush = () => {
    if (text().trim() === "") return setText("");
    if (add([text()])) setText("");
  };

  const remove = (tag: string) => {
    props.onChange(props.value.filter((x) => x !== tag));
    input?.focus();
  };

  return (
    <Field name={props.name ?? "tags"} label={props.label} help={props.help ?? t("ipam.field.tags_help")} error={problem() ?? props.error}>
      {(control) => (
        <div class="tags-input">
          <ul class="tags-chips" aria-label={props.label} data-testid="tags-chips">
            <For each={props.value}>
              {(tag) => (
                <li class="tag" data-tag={tag}>
                  {tag}
                  <button type="button" class="tag-remove" aria-label={t("ipam.field.tag_remove", { tag })} onClick={() => remove(tag)}>
                    <Icon name="x" size="xs" />
                  </button>
                </li>
              )}
            </For>
          </ul>
          <input
            ref={input}
            class="input"
            type="text"
            autocomplete="off"
            {...control}
            value={text()}
            onInput={(e) => {
              const value = e.currentTarget.value;
              if (!value.includes(",")) {
                setText(value);
                setProblem(undefined);
                return;
              }
              const parts = value.split(",");
              const rest = parts.pop() ?? "";
              // The input shows what is left to type; the signal alone would not change an empty input back.
              const shown = add(parts) ? rest : value;
              e.currentTarget.value = shown;
              setText(shown);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && text().trim() !== "") {
                e.preventDefault();
                flush();
              } else if (e.key === "Backspace" && text() === "" && props.value.length > 0) {
                props.onChange(props.value.slice(0, -1));
              }
            }}
            onBlur={flush}
          />
        </div>
      )}
    </Field>
  );
}
