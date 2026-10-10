// The form of a connector's settings (docs/plugins.md, section 5, "The settings schema").
// `settingsForm()` (schema.ts) turns the manifest's schema into fields; this component draws
// them and edits a JSON object of values. It is controlled: it reads `values` and calls
// `onChange` with a whole new object on every edit, never mutating the one it was given.
// Errors arrive as translated messages by field path (`settings.url`, `settings.ssids[1]`,
// `settings.group.name`), from `checkSettings` and from the server's field errors alike.
//
// - Empty text in a string or number control means "not set": the value becomes `undefined`.
// - A number control keeps text that is not a finite number as the raw string, so that
//   `checkSettings` reports the `type` problem instead of the form dropping the input.
// - A boolean that was never touched shows its default without calling `onChange`.
// - Lists of strings or integers are a fieldset of item controls; an added item is `""` until
//   something is typed (an `undefined` cannot be part of a JSON array).
// - A group (one level of nested fields) reads and writes the nested object.
// - Unsupported settings are shown read-only and pass through unchanged.
import { createEffect, createMemo, For, Index, Match, on, Show, Switch, type JSX } from "solid-js";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import type { ArrayField, BooleanField, GroupField, NumberField, SettingField, Settings, SettingsForm, StringField, UnsupportedField } from "./schema";
import "./schema-form.css";

export interface SchemaFormProps {
  form: SettingsForm;
  /** The current values (a JSON object of the schema's properties, groups as nested objects). */
  values: Settings;
  /** Called with the whole new object on every edit; never mutate `values`. */
  onChange: (values: Settings) => void;
  /** Translated messages by field path: `settings.url`, `settings.ssids[1]` (an item), `settings.group.name`. */
  errors: Readonly<Record<string, string>>;
  disabled?: boolean;
  /** Prefix of the element ids, so two forms on a page do not collide (default "sf"). */
  idPrefix?: string;
}

// ---------------------------------------------------------------------------------
// Context of the render functions

/** What every field of a form shares. The members are getters over the props. */
interface Env {
  readonly errors: Readonly<Record<string, string>>;
  readonly disabled: boolean;
  readonly prefix: string;
}

/** The object a list of fields edits: where it reads its values and where the new object goes. */
interface Scope {
  readonly env: Env;
  readonly values: () => Settings;
  readonly change: (values: Settings) => void;
}

/** Attributes spread onto a control. */
type Attrs = Record<string, string | undefined>;

/** The element ids, test id, attributes and notes of one field. */
interface Control {
  id: string;
  noteId: string;
  /** The field path of the setting (`settings.url`), which names its error in `data-field`. */
  path: string;
  help: () => string | undefined;
  error: () => string | undefined;
  /** For an input or select with its own label. */
  attrs: Attrs;
  /** For a fieldset (a list or a group), which names itself by its legend. */
  fieldset: Attrs;
}

/** The text a number control shows for a text it could not turn into a number. */
const BAD_NUMBER = "NaN";

/** Formats whose values are identifiers rather than words. */
const MONO_FORMATS: readonly (string | undefined)[] = ["uri", "hostname", "ipv4", "ipv6"];

const dashed = (path: string) => path.replaceAll(".", "-");

const labelOf = (f: Pick<SettingField, "title" | "name">) => (f.title?.trim() ? f.title : f.name);

/** The text of a stored value in a text control. */
function text(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === undefined || v === null) return "";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return json(v) ?? "";
}

function json(v: unknown): string | undefined {
  try {
    return JSON.stringify(v);
  } catch {
    return undefined;
  }
}

/** The text of a stored value in a number control: a number, or a text kept as it was typed. */
function numberText(v: unknown): string {
  if (typeof v === "number") return String(v);
  return typeof v === "string" && v !== BAD_NUMBER ? v : "";
}

/** The first example that a person can read as one: a non-empty string or a number. */
function exampleOf(examples: readonly unknown[]): string | undefined {
  const found = examples.find((e) => (typeof e === "string" && e !== "") || typeof e === "number");
  return found === undefined ? undefined : String(found);
}

function defaultOf(f: SettingField): string | undefined {
  switch (f.type) {
    case "string":
      return f.default === undefined || f.default === "" ? undefined : f.default;
    case "integer":
    case "number":
      return f.default === undefined ? undefined : String(f.default);
    case "boolean":
      // There is no word for an off default; an unchecked box says as much.
      return f.default === true ? t("connectors.form.on") : undefined;
    default:
      return undefined;
  }
}

/** The help line: the description, the default and the first example, joined with a space. */
function helpOf(f: SettingField): string | undefined {
  const parts: string[] = [];
  if (f.description) parts.push(f.description);
  const def = defaultOf(f);
  if (def !== undefined) parts.push(t("connectors.form.default", { value: def }));
  const example = exampleOf(f.examples);
  if (example !== undefined) parts.push(t("connectors.form.example", { value: example }));
  return parts.length > 0 ? parts.join(" ") : undefined;
}

function controlOf(f: SettingField, scope: Scope, helpText: () => string | undefined = () => helpOf(f)): Control {
  const id = `${scope.env.prefix}-${dashed(f.path)}`;
  const noteId = `${id}-note`;
  const testid = `field-${dashed(f.path)}`;
  const error = () => scope.env.errors[f.path] || undefined;
  const describedby = () => (error() || helpText() ? noteId : undefined);
  return {
    id,
    noteId,
    path: f.path,
    help: helpText,
    error,
    attrs: {
      id,
      "data-testid": testid,
      get "aria-invalid"() {
        return error() ? "true" : undefined;
      },
      get "aria-describedby"() {
        return describedby();
      },
      get "aria-required"() {
        return f.required ? "true" : undefined;
      },
    },
    fieldset: {
      id,
      "data-testid": testid,
      get "aria-describedby"() {
        return describedby();
      },
    },
  };
}

/** A copy of the values with one member replaced. */
function put(scope: Scope, name: string, value: unknown): void {
  scope.change({ ...scope.values(), [name]: value });
}

// ---------------------------------------------------------------------------------
// Pieces

/**
 * The line under a control: its error with a glyph (never color alone), else its help. The
 * error is `data-testid="field-error"`; `field` is the setting's path (`settings.url`, for an
 * item `settings.ssids[1]`), the same path as the control's `field-settings-url`.
 */
function Note(props: { id: string; field: string; help?: string | undefined; error?: string | undefined }) {
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
      <span class="help bad sf-note" id={props.id} role="alert" data-testid="field-error" data-field={props.field}>
        <Icon name="alert" size="xs" />
        {props.error}
      </span>
    </Show>
  );
}

/** A label, one control and the note under it. */
function Frame(props: { field: SettingField; c: Control; children: JSX.Element }) {
  return (
    <div class="field">
      <label for={props.c.id} classList={{ required: props.field.required }}>
        {labelOf(props.field)}
      </label>
      {props.children}
      <Note id={props.c.noteId} field={props.c.path} help={props.c.help()} error={props.c.error()} />
    </div>
  );
}

/**
 * A select over the values of an enum. The first option "not set" is there when the setting
 * is optional, and also while a required one has no value (otherwise the select would show
 * its first value while the setting is empty). A value outside the enum stays selectable, so
 * the select never shows something else than what is stored.
 */
function EnumSelect(props: {
  attrs: Attrs;
  options: readonly string[];
  value: string;
  required: boolean;
  disabled: boolean;
  onPick: (raw: string) => void;
}) {
  const choices = createMemo(() => {
    const out: string[] = [];
    if (!props.required || props.value === "") out.push("");
    out.push(...props.options);
    if (props.value !== "" && !props.options.includes(props.value)) out.push(props.value);
    return out;
  });
  return (
    <select {...props.attrs} class="select" disabled={props.disabled} onChange={(e) => props.onPick(e.currentTarget.value)}>
      <For each={choices()}>
        {(v) => (
          <option value={v} selected={v === props.value}>
            {v === "" ? t("connectors.form.choose") : v}
          </option>
        )}
      </For>
    </select>
  );
}

/**
 * What a number control sends for what is typed. An empty input is `empty`; text that is not
 * a finite number stays the raw string. A browser hides text it cannot read as a number (the
 * input then reports `badInput` and an empty value): that becomes `BAD_NUMBER`, a string, so
 * the `type` problem is reported.
 */
function parseNumber(input: HTMLInputElement, empty: "" | undefined): unknown {
  const raw = input.value;
  if (raw.trim() === "") return input.validity.badInput ? BAD_NUMBER : empty;
  const n = Number(raw);
  return Number.isFinite(n) ? n : raw;
}

/**
 * A number input. The stored value is written back to the input only when it says something
 * else than the input already does, so typing "0." or "1e" is not rewritten under the cursor.
 */
function NumberInput(props: {
  attrs: Attrs;
  value: unknown;
  empty: "" | undefined;
  integer: boolean;
  min: number | undefined;
  max: number | undefined;
  placeholder: string | undefined;
  disabled: boolean;
  onValue: (value: unknown) => void;
}) {
  let input: HTMLInputElement | undefined;
  createEffect(
    on(
      () => numberText(props.value),
      (next) => {
        if (!input || props.value === BAD_NUMBER) return;
        const typed = input.value;
        if (typed === next) return;
        if (typed !== "" && next !== "" && Number(typed) === Number(next)) return;
        input.value = next;
      },
    ),
  );
  return (
    <input
      {...props.attrs}
      ref={input}
      type="number"
      class="input num"
      min={props.min}
      max={props.max}
      step={props.integer ? 1 : "any"}
      placeholder={props.placeholder}
      disabled={props.disabled}
      onInput={(e) => props.onValue(parseNumber(e.currentTarget, props.empty))}
    />
  );
}

// ---------------------------------------------------------------------------------
// Fields

function stringField(f: StringField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope);
  const value = () => text(scope.values()[f.name]);
  const set = (raw: string) => put(scope, f.name, raw === "" ? undefined : raw);
  const options = f.enum && f.enum.length > 0 ? f.enum : undefined;
  return (
    <Frame field={f} c={c}>
      {options ? (
        <EnumSelect attrs={c.attrs} options={options} value={value()} required={f.required} disabled={scope.env.disabled} onPick={set} />
      ) : (
        <input
          {...c.attrs}
          type="text"
          class={MONO_FORMATS.includes(f.format) ? "input mono" : "input"}
          spellcheck={false}
          autocomplete="off"
          placeholder={exampleOf(f.examples)}
          disabled={scope.env.disabled}
          value={value()}
          onInput={(e) => set(e.currentTarget.value)}
        />
      )}
    </Frame>
  );
}

function numberField(f: NumberField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope);
  const value = () => scope.values()[f.name];
  const options = f.enum && f.enum.length > 0 ? f.enum : undefined;
  return (
    <Frame field={f} c={c}>
      {options ? (
        <EnumSelect
          attrs={c.attrs}
          options={options.map(String)}
          value={numberText(value())}
          required={f.required}
          disabled={scope.env.disabled}
          onPick={(raw) => put(scope, f.name, raw === "" ? undefined : Number(raw))}
        />
      ) : (
        <NumberInput
          attrs={c.attrs}
          value={value()}
          empty={undefined}
          integer={f.type === "integer"}
          min={f.minimum}
          max={f.maximum}
          placeholder={exampleOf(f.examples)}
          disabled={scope.env.disabled}
          onValue={(v) => put(scope, f.name, v)}
        />
      )}
    </Frame>
  );
}

function booleanField(f: BooleanField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope);
  const checked = () => {
    const v = scope.values()[f.name];
    if (typeof v === "boolean") return v;
    return v === undefined || v === null ? (f.default ?? false) : false;
  };
  return (
    <div class="field">
      <label class="sf-check" classList={{ required: f.required }}>
        <input
          {...c.attrs}
          type="checkbox"
          class="cb"
          checked={checked()}
          disabled={scope.env.disabled}
          onChange={(e) => put(scope, f.name, e.currentTarget.checked)}
        />
        <span>{labelOf(f)}</span>
      </label>
      <Note id={c.noteId} field={c.path} help={c.help()} error={c.error()} />
    </div>
  );
}

/** One item of a list: its control, the button that removes it and the error under it. */
function Item(props: {
  field: ArrayField;
  env: Env;
  base: string;
  label: string;
  index: number;
  value: unknown;
  onEdit: (value: unknown) => void;
  onRemove: () => void;
}) {
  const items = () => props.field.items;
  const stringItems = () => {
    const it = items();
    return it.type === "string" ? it : undefined;
  };
  const numberItems = () => {
    const it = items();
    return it.type === "string" ? undefined : it;
  };
  const path = () => `${props.field.path}[${props.index}]`;
  const error = () => props.env.errors[path()] || undefined;
  const noteId = () => `${props.base}-item-${props.index}-note`;
  const attrs = (): Attrs => ({
    "data-testid": "settings-item",
    "data-field": props.field.name,
    "data-index": String(props.index),
    "aria-label": t("connectors.form.item_label", { field: props.label, n: props.index + 1 }),
    "aria-invalid": error() ? "true" : undefined,
    "aria-describedby": error() ? noteId() : undefined,
  });
  const placeholder = () => exampleOf(items().examples);
  const choices = (): readonly string[] | undefined => {
    const it = items();
    if (!it.enum || it.enum.length === 0) return undefined;
    return it.type === "string" ? it.enum : it.enum.map(String);
  };
  return (
    <li class="sf-item">
      <div class="sf-item-row">
        <Switch>
          <Match when={choices()}>
            {(options) => (
              <EnumSelect
                attrs={attrs()}
                options={options()}
                value={text(props.value)}
                required={false}
                disabled={props.env.disabled}
                onPick={(raw) => props.onEdit(items().type === "string" || raw === "" ? raw : Number(raw))}
              />
            )}
          </Match>
          <Match when={stringItems()}>
            {(it) => (
              <input
                {...attrs()}
                type="text"
                class={MONO_FORMATS.includes(it().format) ? "input mono" : "input"}
                spellcheck={false}
                autocomplete="off"
                placeholder={placeholder()}
                disabled={props.env.disabled}
                value={text(props.value)}
                onInput={(e) => props.onEdit(e.currentTarget.value)}
              />
            )}
          </Match>
          <Match when={numberItems()}>
            {(it) => (
              <NumberInput
                attrs={attrs()}
                value={props.value}
                empty=""
                integer={it().type === "integer"}
                min={it().minimum}
                max={it().maximum}
                placeholder={placeholder()}
                disabled={props.env.disabled}
                onValue={props.onEdit}
              />
            )}
          </Match>
        </Switch>
        <button
          type="button"
          class="icon-btn"
          data-testid="settings-item-remove"
          data-field={props.field.name}
          data-index={props.index}
          aria-label={t("connectors.form.item_remove", { n: props.index + 1, field: props.label })}
          disabled={props.env.disabled}
          onClick={() => props.onRemove()}
        >
          <Icon name="x" />
        </button>
      </div>
      <Show when={error()}>
        <Note id={noteId()} field={path()} error={error()} />
      </Show>
    </li>
  );
}

function arrayField(f: ArrayField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope);
  const label = labelOf(f);
  let fieldset: HTMLFieldSetElement | undefined;
  let addButton: HTMLButtonElement | undefined;
  const items = (): readonly unknown[] => {
    const v = scope.values()[f.name];
    return Array.isArray(v) ? (v as unknown[]) : [];
  };
  const set = (next: unknown[]) => put(scope, f.name, next);
  const atMax = () => f.maxItems !== undefined && items().length >= f.maxItems;

  /** Moves the focus once the parent has rendered the new list. */
  const focusItem = (index: number) =>
    queueMicrotask(() => {
      if (index < 0) addButton?.focus();
      else fieldset?.querySelector<HTMLElement>(`[data-testid="settings-item"][data-index="${index}"]`)?.focus();
    });
  const add = () => {
    const next = [...items(), ""];
    set(next);
    focusItem(next.length - 1);
  };
  const edit = (index: number, value: unknown) => {
    const next = [...items()];
    next[index] = value;
    set(next);
  };
  const remove = (index: number) => {
    const next = items().filter((_, i) => i !== index);
    set(next);
    // The button that was pressed is gone: the focus goes to the item that took its place.
    focusItem(Math.min(index, next.length - 1));
  };

  return (
    <fieldset {...c.fieldset} ref={fieldset} class="sf-set">
      <legend classList={{ required: f.required }}>{label}</legend>
      <Show when={items().length > 0} fallback={<p class="muted sf-empty">{t("connectors.form.items_empty")}</p>}>
        <ul class="sf-items">
          <Index each={items()}>
            {(item, i) => (
              <Item
                field={f}
                env={scope.env}
                base={c.id}
                label={label}
                index={i}
                value={item()}
                onEdit={(value) => edit(i, value)}
                onRemove={() => remove(i)}
              />
            )}
          </Index>
        </ul>
      </Show>
      <div class="sf-add">
        <button
          type="button"
          class="btn sm"
          ref={addButton}
          data-testid="settings-item-add"
          data-field={f.name}
          aria-label={t("connectors.form.item_add_to", { field: label })}
          disabled={scope.env.disabled || atMax()}
          onClick={add}
        >
          <Icon name="plus" size="sm" /> {t("connectors.form.item_add")}
        </button>
      </div>
      <Note id={c.noteId} field={c.path} help={c.help()} error={c.error()} />
    </fieldset>
  );
}

function groupField(f: GroupField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope);
  const inner = (): Settings => {
    const v = scope.values()[f.name];
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Settings) : {};
  };
  const child: Scope = { env: scope.env, values: inner, change: (next) => put(scope, f.name, next) };
  return (
    <fieldset {...c.fieldset} class="sf-set">
      <legend classList={{ required: f.required }}>{labelOf(f)}</legend>
      <Note id={c.noteId} field={c.path} help={c.help()} error={c.error()} />
      <div class="sf-fields">
        <Fields fields={f.fields} scope={child} />
      </div>
    </fieldset>
  );
}

function unsupportedField(f: UnsupportedField, scope: Scope): JSX.Element {
  const c = controlOf(f, scope, () => t("connectors.form.unsupported"));
  const labelId = `${c.id}-label`;
  const shown = () => {
    const v = scope.values()[f.name];
    return (v === undefined ? undefined : json(v)) ?? "—";
  };
  return (
    <div class="field" role="group" aria-labelledby={labelId} aria-describedby={c.noteId}>
      <span class="label" id={labelId}>
        {labelOf(f)}
      </span>
      <code class="sf-code mono" data-testid={c.attrs["data-testid"]}>
        {shown()}
      </code>
      <Note id={c.noteId} field={c.path} help={c.help()} error={c.error()} />
    </div>
  );
}

function fieldView(f: SettingField, scope: Scope): JSX.Element {
  switch (f.type) {
    case "string":
      return stringField(f, scope);
    case "integer":
    case "number":
      return numberField(f, scope);
    case "boolean":
      return booleanField(f, scope);
    case "array":
      return arrayField(f, scope);
    case "object":
      return groupField(f, scope);
    case "unsupported":
      return unsupportedField(f, scope);
  }
}

function Fields(props: { fields: readonly SettingField[]; scope: Scope }) {
  return <For each={props.fields}>{(f) => fieldView(f, props.scope)}</For>;
}

export function SchemaForm(props: SchemaFormProps): JSX.Element {
  const scope: Scope = {
    env: {
      get errors() {
        return props.errors;
      },
      get disabled() {
        return props.disabled === true;
      },
      get prefix() {
        return props.idPrefix ?? "sf";
      },
    },
    values: () => props.values,
    change: (values) => props.onChange(values),
  };
  return (
    <Show
      when={props.form.fields.length > 0}
      fallback={
        <p class="muted" data-testid="settings-empty">
          {t("connectors.form.no_settings")}
        </p>
      }
    >
      <div class="sf" data-testid="settings-form">
        <Fields fields={props.form.fields} scope={scope} />
      </div>
    </Show>
  );
}
