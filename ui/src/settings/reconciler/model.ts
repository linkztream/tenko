// The reconciler settings (WP3.11d, WP3.12a; docs/reconciliation.md, section 3.1.1): the wire
// shape is the generated one, and this file holds the units the form shows (the server counts
// seconds), the limits that are checked before anything is sent, and the words for a refusal.
import type { components } from "../../api/generated/schema";
import { ApiError, errorMessage } from "../../api/problem";
import { formatDuration, t, tDynamic } from "../../i18n";

export type ReconcilerSettings = components["schemas"]["ReconcilerSettings"];

export type FieldId = "interval" | "debounce" | "refresh" | "purge" | "orphan" | "retention";
type SecondsKey = Exclude<keyof ReconcilerSettings, "adopt">;
export type Unit = "second" | "minute" | "hour" | "day";

export interface FieldSpec {
  id: FieldId;
  /** The field of the request body. */
  key: SecondsKey;
  unit: Unit;
  /** Seconds in one unit. */
  factor: number;
  /** The limits and the default, in seconds. */
  min: number;
  max: number;
  fallback: number;
}

const DAY = 86_400;

/** In the order of the form: how often it runs, how long facts live. */
export const FIELDS: readonly FieldSpec[] = [
  { id: "interval", key: "interval_secs", unit: "second", factor: 1, min: 30, max: DAY, fallback: 300 },
  { id: "debounce", key: "debounce_secs", unit: "second", factor: 1, min: 0, max: 300, fallback: 2 },
  { id: "refresh", key: "refresh_secs", unit: "minute", factor: 60, min: 60, max: DAY, fallback: 900 },
  { id: "purge", key: "purge_interval_secs", unit: "hour", factor: 3_600, min: 300, max: DAY, fallback: 3_600 },
  { id: "orphan", key: "orphan_after_secs", unit: "day", factor: DAY, min: 3_600, max: 365 * DAY, fallback: 7 * DAY },
  { id: "retention", key: "retention_secs", unit: "day", factor: DAY, min: DAY, max: 365 * DAY, fallback: 30 * DAY },
];

/** The form's values as typed: text per number, so that a half-typed value is not lost. */
export interface Draft {
  adopt: boolean;
  text: Record<FieldId, string>;
}

/** Seconds in the unit of the field, without trailing noise: 300 s as hours is "0.0833". */
export function displayOf(spec: FieldSpec, seconds: number): string {
  return String(Number((seconds / spec.factor).toFixed(4)));
}

export function draftOf(settings: ReconcilerSettings): Draft {
  const text = {} as Record<FieldId, string>;
  for (const spec of FIELDS) text[spec.id] = displayOf(spec, settings[spec.key]);
  return { adopt: settings.adopt, text };
}

/**
 * The seconds a field stands for: the stored value while the text is the one shown for it (so
 * that 300 s shown as 0.0833 hours is not rounded by saving), else the typed number converted;
 * `NaN` when the text is not a number or not a whole number of seconds.
 */
export function secondsOf(spec: FieldSpec, text: string, stored: number): number {
  if (text.trim() === displayOf(spec, stored)) return stored;
  if (text.trim() === "") return Number.NaN;
  const raw = Number(text.trim()) * spec.factor;
  return Number.isFinite(raw) && Math.abs(raw - Math.round(raw)) < 1e-6 ? Math.round(raw) : Number.NaN;
}

export type DraftErrors = Partial<Record<FieldId, string>>;

/** The problems of a draft; a key is present only when that field is wrong. */
export function draftErrors(draft: Draft, stored: ReconcilerSettings): DraftErrors {
  const errors: DraftErrors = {};
  const seconds = {} as Record<FieldId, number>;
  for (const spec of FIELDS) {
    const value = secondsOf(spec, draft.text[spec.id], stored[spec.key]);
    seconds[spec.id] = value;
    if (!(value >= spec.min && value <= spec.max)) {
      errors[spec.id] = t("reconciler.error.range", { min: formatDuration(spec.min), max: formatDuration(spec.max) });
    }
  }
  if (errors.refresh === undefined && errors.retention === undefined && seconds.refresh >= seconds.retention) {
    errors.refresh = t("reconciler.error.refresh", { retention: formatDuration(seconds.retention) });
  }
  return errors;
}

/** The request body: all settings, in seconds. */
export function body(draft: Draft, stored: ReconcilerSettings): ReconcilerSettings {
  const out: ReconcilerSettings = { ...stored, adopt: draft.adopt };
  for (const spec of FIELDS) out[spec.key] = secondsOf(spec, draft.text[spec.id], stored[spec.key]);
  return out;
}

/** The limits of a field in words, for the line under it: "30 s to 1 d, default 5 min". */
export function limitsText(spec: FieldSpec): string {
  return t("reconciler.limits", { min: formatDuration(spec.min), max: formatDuration(spec.max), default: formatDuration(spec.fallback) });
}

/** A field of the request body by the name the server reports it under. */
function fieldLabel(field: string | undefined): string {
  const spec = FIELDS.find((f) => f.key === field);
  return (spec && tDynamic(`reconciler.field.${spec.id}`)) || (field ?? "");
}

/**
 * The words of a refused save. The server's 422 names the field; the text lives in this page's
 * own key because the key for the code would sit in the discovery pack, which this page does not load.
 */
export function saveErrorText(err: unknown): string {
  if (err instanceof ApiError && err.code === "ipam.reconciler.settings.invalid") {
    return t("reconciler.error.invalid", { field: fieldLabel(err.params["field"]) });
  }
  return errorMessage(err);
}

/** The unit shown beside a field: "seconds", "minutes", "hours", "days". */
export function unitText(unit: Unit): string {
  return tDynamic(`reconciler.unit.${unit}`) ?? unit;
}

