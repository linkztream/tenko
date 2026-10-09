// Reading the members of a request body or command argument. A `Body` collects the field
// errors of everything it reads (one `ipam.validation` with all of them), refuses unknown
// members like the server does (`deny_unknown_fields`) and follows merge-patch rules: an
// absent member is `undefined`, an explicit `null` is `null`.
import { formatIp, parseIp, type Ip } from "../../../ipam/ip";
import type { UtilizationAlarm } from "../../types";
import { isUuid } from "../util";
import { invalidFields, unknownField } from "./problems";

export type Json = Record<string, unknown>;

export function isJson(value: unknown): value is Json {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

const MAX_NAME = 128;
const MAX_DESCRIPTION = 4096;
const MAX_TAG = 64;
const KEY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

export class Body {
  private readonly errors: { field: string; detail: string }[] = [];

  constructor(
    readonly raw: Json,
    private readonly prefix = "",
  ) {}

  /** Refuses members the document does not know. */
  only(allowed: readonly string[]): this {
    for (const key of Object.keys(this.raw)) {
      if (!allowed.includes(key)) throw unknownField(key, allowed);
    }
    return this;
  }

  add(key: string, detail: string): void {
    this.errors.push({ field: this.prefix + key, detail });
  }

  /** Takes over the errors a nested body collected. */
  absorb(child: Body): void {
    this.errors.push(...child.errors);
  }

  /** Throws `ipam.validation` with every error read so far. */
  done(): void {
    if (this.errors.length > 0) throw invalidFields(this.errors);
  }

  has(key: string): boolean {
    return this.raw[key] !== undefined;
  }

  /** Whether the member is absent or `null`. */
  missing(key: string): boolean {
    const value = this.raw[key];
    return value === undefined || value === null;
  }

  // ---- text -----------------------------------------------------------------------------

  private text(key: string, max: number, label: string): string | undefined {
    const value = this.raw[key];
    if (typeof value !== "string") {
      this.add(key, `${key} must be a text`);
      return undefined;
    }
    const trimmed = value.trim();
    if (trimmed === "" || Array.from(trimmed).length > max) {
      this.add(key, `${label} must be 1 to ${max} characters`);
      return undefined;
    }
    if (CONTROL.test(trimmed)) {
      this.add(key, `${label} must not contain control characters`);
      return undefined;
    }
    return trimmed;
  }

  /** A required name (1 to 128 characters, no control characters). */
  reqName(key: string): string {
    if (this.missing(key)) {
      this.add(key, `${key} is required`);
      return "";
    }
    return this.text(key, MAX_NAME, key) ?? "";
  }

  /** A name that is left alone when absent or `null`. */
  name(key: string): string | undefined {
    return this.missing(key) ? undefined : this.text(key, MAX_NAME, key);
  }

  /** An optional text: absent is `undefined`, `null` and blank clear it. */
  clearable(key: string): string | null | undefined {
    const value = this.raw[key];
    if (value === undefined) return undefined;
    if (value === null) return null;
    if (typeof value === "string" && value.trim() === "") return null;
    return this.text(key, MAX_NAME, key) ?? null;
  }

  /** `description`: absent is `undefined`, `null` and blank clear it. */
  description(): string | null | undefined {
    const value = this.raw.description;
    if (value === undefined) return undefined;
    if (value === null) return null;
    if (typeof value !== "string") {
      this.add("description", "description must be a text");
      return null;
    }
    const trimmed = value.trim();
    if (trimmed === "") return null;
    if (Array.from(trimmed).length > MAX_DESCRIPTION) {
      this.add("description", `description must be at most ${MAX_DESCRIPTION} characters`);
      return null;
    }
    return trimmed;
  }

  /** A required text that is kept as given. */
  reqString(key: string): string {
    const value = this.raw[key];
    if (value === undefined || value === null) {
      this.add(key, `${key} is required`);
      return "";
    }
    if (typeof value !== "string") {
      this.add(key, `${key} must be a text`);
      return "";
    }
    return value;
  }

  /** A text member kept as given; absent and `null` are `undefined`. */
  string(key: string): string | undefined {
    const value = this.raw[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== "string") {
      this.add(key, `${key} must be a text`);
      return undefined;
    }
    return value;
  }

  /** A text member where `null` clears: absent is `undefined`. */
  nullableString(key: string): string | null | undefined {
    const value = this.raw[key];
    if (value === undefined) return undefined;
    if (value === null) return null;
    if (typeof value !== "string") {
      this.add(key, `${key} must be a text or null`);
      return undefined;
    }
    return value;
  }

  // ---- identifiers ----------------------------------------------------------------------

  private idOf(key: string, value: unknown): string | undefined {
    if (typeof value !== "string" || !isUuid(value)) {
      this.add(key, `${key} must be an identifier (a UUID)`);
      return undefined;
    }
    return value.toLowerCase();
  }

  /** A UUID member; absent and `null` are `undefined`. */
  uuid(key: string): string | undefined {
    return this.missing(key) ? undefined : this.idOf(key, this.raw[key]);
  }

  /** A required UUID member. */
  reqUuid(key: string): string {
    if (this.missing(key)) {
      this.add(key, `${key} is required`);
      return "";
    }
    return this.idOf(key, this.raw[key]) ?? "";
  }

  /** A reference where `null` clears: absent is `undefined`. */
  nullUuid(key: string): string | null | undefined {
    const value = this.raw[key];
    if (value === undefined) return undefined;
    if (value === null) return null;
    return this.idOf(key, value);
  }

  // ---- values ---------------------------------------------------------------------------

  /** One of `values`; absent and `null` are `undefined`. */
  oneOf<T extends string>(key: string, values: readonly T[]): T | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (typeof value !== "string" || !(values as readonly string[]).includes(value)) {
      this.add(key, `${key} must be one of ${values.join(", ")}`);
      return undefined;
    }
    return value as T;
  }

  reqOneOf<T extends string>(key: string, values: readonly T[]): T {
    if (this.missing(key)) {
      this.add(key, `${key} is required`);
      return values[0] as T;
    }
    return this.oneOf(key, values) ?? (values[0] as T);
  }

  /** An integer in `min..max`; absent and `null` are `undefined`. */
  integer(key: string, min: number, max: number): number | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
      this.add(key, `${key} must be a whole number from ${min} to ${max}`);
      return undefined;
    }
    return value;
  }

  reqInteger(key: string, min: number, max: number): number {
    if (this.missing(key)) {
      this.add(key, `${key} is required`);
      return min;
    }
    return this.integer(key, min, max) ?? min;
  }

  /** An integer where `null` clears: absent is `undefined`. */
  nullableInteger(key: string, min: number, max: number): number | null | undefined {
    if (this.raw[key] === undefined) return undefined;
    if (this.raw[key] === null) return null;
    return this.integer(key, min, max);
  }

  bool(key: string): boolean | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (typeof value !== "boolean") {
      this.add(key, `${key} must be true or false`);
      return undefined;
    }
    return value;
  }

  /** The tags as a sorted set; absent and `null` are `undefined`. */
  tags(key = "tags"): string[] | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (!Array.isArray(value)) {
      this.add(key, `${key} must be a list of tags`);
      return undefined;
    }
    const out = new Set<string>();
    value.forEach((entry, index) => {
      const tag = typeof entry === "string" ? entry.trim() : "";
      if (tag === "" || Array.from(tag).length > MAX_TAG || CONTROL.test(tag)) {
        this.add(`${key}[${index}]`, "a tag must be 1 to 64 characters without control characters");
      } else {
        out.add(tag);
      }
    });
    return [...out].sort();
  }

  /**
   * The custom values: an object by field key. Values are checked against the definitions
   * by the planner; here only the keys and the shape of each value are read. A `null`
   * value stays (a patch removes the value).
   */
  custom(key = "custom"): Json | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (!isJson(value)) {
      this.add(key, `${key} must be an object of custom field values`);
      return undefined;
    }
    const out: Json = {};
    for (const [field, entry] of Object.entries(value)) {
      if (!KEY_PATTERN.test(field)) {
        this.add(`${key}.${field}`, `${field} is not a custom field key`);
      } else {
        out[field] = entry;
      }
    }
    return out;
  }

  /** Utilization alarm thresholds: `warn_pct < crit_pct <= 100`; `null` clears. */
  alarm(key = "alarm"): UtilizationAlarm | null | undefined {
    const value = this.raw[key];
    if (value === undefined) return undefined;
    if (value === null) return null;
    if (!isJson(value)) {
      this.add(key, `${key} must be an object with warn_pct and crit_pct`);
      return undefined;
    }
    const inner = new Body(value, `${this.prefix}${key}.`);
    const warn = inner.reqInteger("warn_pct", 0, 255);
    const crit = inner.reqInteger("crit_pct", 0, 255);
    inner.errors.forEach((e) => this.errors.push(e));
    if (inner.errors.length > 0) return undefined;
    if (!(warn < crit && crit <= 100)) {
      this.add(key, "the warning threshold must be below the critical one, and critical at most 100");
      return undefined;
    }
    return { warn_pct: warn, crit_pct: crit };
  }

  /** The revision a caller read; absent and `null` are `null`. */
  expected(key = "expected"): number | null {
    return this.integer(key, 0, Number.MAX_SAFE_INTEGER) ?? null;
  }

  /** A required nested object. */
  reqObject(key: string): Json {
    const value = this.raw[key];
    if (value === undefined || value === null) {
      this.add(key, `${key} is required`);
      return {};
    }
    if (!isJson(value)) {
      this.add(key, `${key} must be an object`);
      return {};
    }
    return value;
  }

  /** An optional list of objects. */
  objects(key: string): Json[] | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    if (!Array.isArray(value) || !value.every(isJson)) {
      this.add(key, `${key} must be a list of objects`);
      return undefined;
    }
    return value as Json[];
  }

  /** An address member parsed with the strict parser. */
  ip(key: string): Ip | undefined {
    if (this.missing(key)) return undefined;
    const value = this.raw[key];
    const parsed = typeof value === "string" ? parseIp(value) : null;
    if (!parsed) {
      this.add(key, `${key} is not an IP address`);
      return undefined;
    }
    return parsed;
  }

  reqIp(key: string): Ip {
    if (this.missing(key)) {
      this.add(key, `${key} is required`);
      return { version: 4, value: 0n };
    }
    return this.ip(key) ?? { version: 4, value: 0n };
  }
}

/** The metadata members every input and patch body has. */
export interface MetaInput {
  tags?: string[] | undefined;
  custom?: Json | undefined;
  description?: string | null | undefined;
}

/** Reads `tags`, `custom` and `description` of a body. */
export function readMeta(body: Body): MetaInput {
  return { tags: body.tags(), custom: body.custom(), description: body.description() };
}

/** The members of every `update_*` command: the object, the revision read and the patch. */
export function readUpdate(
  args: Json,
  allowed: readonly string[],
): { id: string; expected: number | null; patch: Body } {
  const body = new Body(args).only(["expected", "id", "patch"]);
  const id = body.reqUuid("id");
  const expected = body.expected();
  const raw = body.reqObject("patch");
  body.done();
  return { id, expected, patch: new Body(raw).only(allowed) };
}

// ---------------------------------------------------------------------------------
// Normal forms of identifiers the API reads and writes in one form

/** A DNS name in the normal form of the server (lowercase, no trailing dot), or null. */
export function normalizeDnsName(raw: string, minLabels: number): string | null {
  let name = raw.trim();
  if (name.endsWith(".")) name = name.slice(0, -1);
  name = name.toLowerCase();
  if (name === "" || name.length > 253) return null;
  const labels = name.split(".");
  if (labels.length < minLabels) return null;
  for (const label of labels) {
    if (label === "" || label.length > 63) return null;
    if (label.startsWith("-") || label.endsWith("-")) return null;
    if (!/^[a-z0-9_-]+$/.test(label)) return null;
  }
  return name;
}

/** Hexadecimal digits with the separators `:`, `-` and `.` removed, or null. */
export function hexDigits(raw: string): string | null {
  const bare = raw.trim().replace(/[:\-.]/g, "").toLowerCase();
  return /^([0-9a-f]{2})*$/.test(bare) ? bare : null;
}

/** A MAC address as `00:00:5e:00:53:01`, or null. */
export function normalizeMac(raw: string): string | null {
  const bare = hexDigits(raw);
  if (bare === null || bare.length !== 12) return null;
  return bare.match(/../g)?.join(":") ?? null;
}

/** An address in the canonical form, or null. */
export function normalizeIpText(raw: string): string | null {
  const ip = parseIp(raw);
  return ip ? formatIp(ip) : null;
}
