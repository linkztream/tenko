// Pure helpers of the toggle editors: the request body for a value, durations in the unit a
// person thinks in, and the checks that the server makes as well (so the editor can say
// what is wrong before anything is sent).
import type { PasswordPolicy, SessionLifetime, SettingsPatch } from "../api/types";
import type { ToggleSetting } from "./toggles";

/** The PATCH body that sets one setting to `value` (a value as a toggle reports it). */
export function patchFor(setting: ToggleSetting, value: unknown): SettingsPatch {
  switch (setting) {
    case "password_policy":
      return { password_policy: value as PasswordPolicy };
    case "mfa":
      return { mfa: value as NonNullable<SettingsPatch["mfa"]> };
    case "passkey_for_admins":
      return { passkey_for_admins: Boolean(value) };
    case "session":
      return { session: value as SessionLifetime };
    case "token_max_days":
      return { token_max_lifetime: value === null || value === undefined ? "unlimited" : { days: value as number } };
    case "breach_check":
      return { breach_check: value as NonNullable<SettingsPatch["breach_check"]> };
    case "lockout":
      return { lockout: value as NonNullable<SettingsPatch["lockout"]> };
    case "updates":
      return { updates: value as NonNullable<SettingsPatch["updates"]> };
  }
}

export type DurationUnit = "minutes" | "hours" | "days";
export const DURATION_UNITS: readonly DurationUnit[] = ["minutes", "hours", "days"];

const UNIT_SECONDS: Record<DurationUnit, number> = { minutes: 60, hours: 3_600, days: 86_400 };

/** A duration in the largest unit that holds it in whole numbers (at least minutes). */
export function splitDuration(seconds: number): { amount: number; unit: DurationUnit } {
  for (const unit of ["days", "hours"] as const) {
    if (seconds >= UNIT_SECONDS[unit] && seconds % UNIT_SECONDS[unit] === 0) {
      return { amount: seconds / UNIT_SECONDS[unit], unit };
    }
  }
  return { amount: Math.max(1, Math.round(seconds / 60)), unit: "minutes" };
}

/** Seconds in `amount` of `unit`, or undefined unless `amount` is a whole number of at least 1. */
export function toSeconds(amount: string, unit: DurationUnit): number | undefined {
  const text = amount.trim();
  if (!/^\d{1,7}$/.test(text)) return undefined;
  const n = Number(text);
  return n >= 1 ? n * UNIT_SECONDS[unit] : undefined;
}

/** The longest API token maximum the server accepts (100 years). */
export const MAX_TOKEN_DAYS = 36_500;

/** Days from the text of the field, or undefined unless it is a whole number from 1 to 36,500. */
export function toDays(text: string): number | undefined {
  const s = text.trim();
  if (!/^\d{1,6}$/.test(s)) return undefined;
  const n = Number(s);
  return n >= 1 && n <= MAX_TOKEN_DAYS ? n : undefined;
}

export type PolicyField = "min" | "max" | "pattern";

export interface PolicyDraft {
  min: string;
  max: string;
  pattern: string;
}

/** The custom password policy of the form, or the fields that are wrong (as the server checks them). */
export function customPolicy(draft: PolicyDraft): { policy?: PasswordPolicy; errors: Partial<Record<PolicyField, true>> } {
  const errors: Partial<Record<PolicyField, true>> = {};
  const whole = (s: string) => (/^\d{1,5}$/.test(s.trim()) ? Number(s.trim()) : undefined);
  const min = whole(draft.min);
  if (min === undefined || min < 4) errors.min = true;
  const maxText = draft.max.trim();
  const max = maxText === "" ? undefined : whole(maxText);
  if (maxText !== "" && (max === undefined || max < 64 || max > 1024)) errors.max = true;
  if (min !== undefined && !errors.min) {
    if (max !== undefined) {
      if (!errors.max && min > max) errors.max = true;
    } else if (min > 256) {
      errors.min = true;
    }
  }
  const pattern = draft.pattern.trim();
  if (pattern !== "") {
    try {
      new RegExp(`^(?:${pattern})$`, "u");
    } catch {
      errors.pattern = true;
    }
  }
  if (Object.keys(errors).length > 0 || min === undefined) return { errors };
  const policy: PasswordPolicy = { preset: "custom", min_length: min };
  if (max !== undefined) policy.max_length = max;
  if (pattern !== "") policy.pattern = pattern;
  return { policy, errors };
}
