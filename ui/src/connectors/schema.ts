// The settings schema of a plugin manifest as form fields (docs/plugins.md, section 5, "The
// settings schema"): a restricted subset of JSON Schema draft 2020-12, a flat object of
// strings (with `enum`, lengths, `pattern` and the formats `uri`, `hostname`, `ipv4`, `ipv6`),
// integers (with `enum` and bounds), numbers (with bounds), booleans and arrays of strings or
// integers. One level of nested objects is accepted as a group of fields, so a later manifest
// version that groups settings still renders. Anything else becomes an `unsupported` field
// that the form shows read-only.
//
// The form checks what the server checks, with the same problem kinds as the host's codes
// (`connect.settings.<kind>`), and reports them under the field path of the API's field errors:
// `settings.<name>`, `settings.<name>[<index>]`, `settings.<group>.<name>`. The server has the
// last word: its field errors land on the same paths.
import { parseIp } from "../ipam/ip";

/** A JSON Schema document as the manifest carries it (untyped in the API document). */
export type JsonSchema = Record<string, unknown>;

export type ProblemKind = "type" | "unknown" | "required" | "enum" | "length" | "pattern" | "format" | "range" | "items" | "unique";

export interface Problem {
  /** `settings.url`, `settings.queues[2]`. */
  path: string;
  kind: ProblemKind;
  /** Named values for the message: `min`, `max`, `format`, `pattern`. */
  params: Record<string, string>;
}

interface Common {
  /** The property name. */
  name: string;
  /** The field path of API errors: `settings.<name>` or `settings.<group>.<name>`. */
  path: string;
  title: string | undefined;
  description: string | undefined;
  required: boolean;
  examples: readonly unknown[];
}

export interface StringField extends Common {
  type: "string";
  default: string | undefined;
  enum: readonly string[] | undefined;
  minLength: number | undefined;
  maxLength: number | undefined;
  pattern: string | undefined;
  format: "uri" | "hostname" | "ipv4" | "ipv6" | undefined;
}

export interface NumberField extends Common {
  type: "integer" | "number";
  default: number | undefined;
  enum: readonly number[] | undefined;
  minimum: number | undefined;
  maximum: number | undefined;
}

export interface BooleanField extends Common {
  type: "boolean";
  default: boolean | undefined;
}

export interface ArrayField extends Common {
  type: "array";
  /** The schema of each item, without a name of its own. */
  items: StringField | NumberField;
  minItems: number | undefined;
  maxItems: number | undefined;
  uniqueItems: boolean;
}

export interface GroupField extends Common {
  type: "object";
  fields: readonly SettingField[];
}

export interface UnsupportedField extends Common {
  type: "unsupported";
}

export type SettingField = StringField | NumberField | BooleanField | ArrayField | GroupField | UnsupportedField;

export interface SettingsForm {
  title: string | undefined;
  description: string | undefined;
  fields: readonly SettingField[];
}

const FORMATS = ["uri", "hostname", "ipv4", "ipv6"] as const;

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function scalarField(name: string, path: string, schema: JsonSchema, required: boolean): StringField | NumberField | BooleanField | UnsupportedField {
  const common = {
    name,
    path,
    title: str(schema.title),
    description: str(schema.description),
    required,
    examples: Array.isArray(schema.examples) ? schema.examples : [],
  };
  switch (schema.type) {
    case "string": {
      const format = str(schema.format);
      return {
        ...common,
        type: "string",
        default: str(schema.default),
        enum: Array.isArray(schema.enum) ? schema.enum.filter((x): x is string => typeof x === "string") : undefined,
        minLength: num(schema.minLength),
        maxLength: num(schema.maxLength),
        pattern: str(schema.pattern),
        format: (FORMATS as readonly string[]).includes(format ?? "") ? (format as StringField["format"]) : undefined,
      };
    }
    case "integer":
    case "number":
      return {
        ...common,
        type: schema.type,
        default: num(schema.default),
        enum: Array.isArray(schema.enum) ? schema.enum.filter((x): x is number => typeof x === "number") : undefined,
        minimum: num(schema.minimum),
        maximum: num(schema.maximum),
      };
    case "boolean":
      return { ...common, type: "boolean", default: typeof schema.default === "boolean" ? schema.default : undefined };
    default:
      return { ...common, type: "unsupported" };
  }
}

function fieldsOf(schema: JsonSchema, base: string, depth: number): SettingField[] {
  const properties = schema.properties && typeof schema.properties === "object" ? (schema.properties as Record<string, JsonSchema>) : {};
  const required = new Set(Array.isArray(schema.required) ? schema.required.filter((x): x is string => typeof x === "string") : []);
  return Object.entries(properties).map(([name, prop]): SettingField => {
    const path = `${base}.${name}`;
    const req = required.has(name);
    if (prop && typeof prop === "object" && prop.type === "array") {
      const items = prop.items && typeof prop.items === "object" ? scalarField(name, path, prop.items as JsonSchema, false) : null;
      if (!items || items.type === "boolean" || items.type === "unsupported") {
        return { name, path, title: str(prop.title), description: str(prop.description), required: req, examples: [], type: "unsupported" };
      }
      return {
        name,
        path,
        title: str(prop.title),
        description: str(prop.description),
        required: req,
        examples: Array.isArray(prop.examples) ? prop.examples : [],
        type: "array",
        items,
        minItems: num(prop.minItems),
        maxItems: num(prop.maxItems),
        uniqueItems: prop.uniqueItems === true,
      };
    }
    if (prop && typeof prop === "object" && prop.type === "object" && depth === 0) {
      return {
        name,
        path,
        title: str(prop.title),
        description: str(prop.description),
        required: req,
        examples: [],
        type: "object",
        fields: fieldsOf(prop, path, 1),
      };
    }
    return scalarField(name, path, prop && typeof prop === "object" ? prop : {}, req);
  });
}

/** The form of a settings schema; a manifest without one has no settings. */
export function settingsForm(schema: JsonSchema | null | undefined): SettingsForm {
  if (!schema || typeof schema !== "object") return { title: undefined, description: undefined, fields: [] };
  return { title: str(schema.title), description: str(schema.description), fields: fieldsOf(schema, "settings", 0) };
}

// ---------------------------------------------------------------------------------
// Values

/** The settings as the form edits them: a JSON object of the schema's properties. */
export type Settings = Record<string, unknown>;

/** The settings to start a form with: the instance's own, else the defaults of the schema. */
export function initialSettings(form: SettingsForm, current?: Settings | null): Settings {
  const fill = (fields: readonly SettingField[], from: Settings | undefined): Settings => {
    const out: Settings = {};
    for (const f of fields) {
      const own = from?.[f.name];
      if (f.type === "object") {
        out[f.name] = fill(f.fields, own && typeof own === "object" ? (own as Settings) : undefined);
      } else if (own !== undefined) {
        out[f.name] = Array.isArray(own) ? [...own] : own;
      } else if (f.type !== "unsupported" && f.type !== "array" && f.default !== undefined) {
        out[f.name] = f.default;
      }
    }
    return out;
  };
  return fill(form.fields, current ?? undefined);
}

/**
 * The settings to send: empty optional values left out (the host fills in the defaults),
 * empty list items left out, groups without a value left out. Values of unsupported fields
 * pass through unchanged.
 */
export function settingsToSend(form: SettingsForm, values: Settings): Settings {
  const clean = (fields: readonly SettingField[], from: Settings): Settings => {
    const out: Settings = {};
    for (const f of fields) {
      const v = from[f.name];
      if (f.type === "object") {
        const inner = clean(f.fields, v && typeof v === "object" ? (v as Settings) : {});
        if (Object.keys(inner).length > 0 || f.required) out[f.name] = inner;
      } else if (v === undefined || v === null || v === "") {
        continue;
      } else if (Array.isArray(v)) {
        // Items added but never typed into are not settings.
        const items = v.filter((item) => item !== "" && item !== undefined && item !== null);
        if (items.length > 0 || f.required) out[f.name] = items;
      } else {
        out[f.name] = v;
      }
    }
    return out;
  };
  return clean(form.fields, values);
}

// ---------------------------------------------------------------------------------
// Checks (the host's rules, docs/plugins.md section 5)

const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;

export function validFormat(format: NonNullable<StringField["format"]>, value: string): boolean {
  switch (format) {
    case "uri":
      // A scheme, a colon and a non-empty rest, without whitespace or control characters.
      return /^[A-Za-z][A-Za-z0-9+.-]*:[^\s\p{Cc}]+$/u.test(value);
    case "hostname": {
      const name = value.replace(/\.$/, "");
      return name.length <= 253 && name.split(".").every((label) => HOST_LABEL.test(label));
    }
    case "ipv4":
      return parseIp(value)?.version === 4 && /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
    case "ipv6":
      // parseIp trims; the host takes no surrounding space.
      return value === value.trim() && parseIp(value)?.version === 6;
  }
}

/** A JavaScript pattern, unanchored like the `is_match` of the Rust regex crate; null when it does not compile. */
function compilePattern(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, "u");
  } catch {
    try {
      return new RegExp(pattern);
    } catch {
      return null;
    }
  }
}

function checkScalar(f: StringField | NumberField, value: unknown, path: string, out: Problem[]): void {
  if (f.type === "string") {
    if (typeof value !== "string") return void out.push({ path, kind: "type", params: { type: "string" } });
    if (f.enum && !f.enum.includes(value)) return void out.push({ path, kind: "enum", params: { values: f.enum.join(", ") } });
    const length = [...value].length;
    if ((f.minLength !== undefined && length < f.minLength) || (f.maxLength !== undefined && length > f.maxLength)) {
      return void out.push({ path, kind: "length", params: { min: String(f.minLength ?? 0), max: String(f.maxLength ?? "") } });
    }
    if (f.pattern !== undefined) {
      const re = compilePattern(f.pattern);
      if (re && !re.test(value)) return void out.push({ path, kind: "pattern", params: { pattern: f.pattern } });
    }
    if (f.format && !validFormat(f.format, value)) out.push({ path, kind: "format", params: { format: f.format } });
    return;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || (f.type === "integer" && !Number.isInteger(value))) {
    return void out.push({ path, kind: "type", params: { type: f.type } });
  }
  if (f.enum && !f.enum.includes(value)) return void out.push({ path, kind: "enum", params: { values: f.enum.join(", ") } });
  if ((f.minimum !== undefined && value < f.minimum) || (f.maximum !== undefined && value > f.maximum)) {
    out.push({ path, kind: "range", params: { min: String(f.minimum ?? ""), max: String(f.maximum ?? "") } });
  }
}

/** Every problem of the settings, in field order; an empty list when they are valid. */
export function checkSettings(form: SettingsForm, values: Settings): Problem[] {
  const out: Problem[] = [];
  const walk = (fields: readonly SettingField[], from: Settings) => {
    for (const f of fields) {
      const v = from[f.name];
      const empty = v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0 && f.required);
      if (empty) {
        if (f.required) out.push({ path: f.path, kind: "required", params: {} });
        continue;
      }
      switch (f.type) {
        case "string":
        case "integer":
        case "number":
          checkScalar(f, v, f.path, out);
          break;
        case "boolean":
          if (typeof v !== "boolean") out.push({ path: f.path, kind: "type", params: { type: "boolean" } });
          break;
        case "array": {
          if (!Array.isArray(v)) {
            out.push({ path: f.path, kind: "type", params: { type: "array" } });
            break;
          }
          if ((f.minItems !== undefined && v.length < f.minItems) || (f.maxItems !== undefined && v.length > f.maxItems)) {
            out.push({ path: f.path, kind: "items", params: { min: String(f.minItems ?? 0), max: String(f.maxItems ?? "") } });
          }
          v.forEach((item, i) => checkScalar(f.items, item, `${f.path}[${i}]`, out));
          if (f.uniqueItems && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) {
            out.push({ path: f.path, kind: "unique", params: {} });
          }
          break;
        }
        case "object":
          if (typeof v !== "object" || Array.isArray(v)) out.push({ path: f.path, kind: "type", params: { type: "object" } });
          else walk(f.fields, v as Settings);
          break;
        case "unsupported":
          break;
      }
    }
  };
  walk(form.fields, values);
  return out;
}

/** The field a problem path belongs to: `settings.ssids[1]` belongs to `settings.ssids`. */
export function fieldOfPath(path: string): string {
  return path.replace(/\[\d+\]$/, "");
}
