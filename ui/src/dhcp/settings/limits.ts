// The limits per client and per scope of the DHCP server settings: the five numbers of the form
// (text) to the object the server takes, with the bounds the server enforces, and the other way.
import type { components } from "../../api/generated/schema";

export type Limits = components["schemas"]["DhcpLimits"];
export type EffectiveLimits = components["schemas"]["DhcpEffectiveLimits"];

export type LimitName = "leases_per_mac" | "addresses_per_duid" | "prefixes_per_duid" | "offers_per_second" | "renew_cache_percent";

/** The limits in the order of the form, each with the largest value the server takes (0 turns it off). */
export const LIMITS: readonly { name: LimitName; max: number }[] = [
  { name: "leases_per_mac", max: 65_535 },
  { name: "addresses_per_duid", max: 65_535 },
  { name: "prefixes_per_duid", max: 65_535 },
  { name: "offers_per_second", max: 100_000 },
  { name: "renew_cache_percent", max: 50 },
];

export type LimitDraft = Record<LimitName, string>;

/** Whether the stored limits set at least one value; an empty object follows the profile like none. */
export function limitsStored(limits: Limits | null | undefined): boolean {
  return limits !== undefined && limits !== null && LIMITS.some(({ name }) => limits[name] !== undefined && limits[name] !== null);
}

/** The form's text: the stored value, else the one in force. */
export function limitDraft(stored: Limits | null | undefined, effective: EffectiveLimits): LimitDraft {
  const out = {} as LimitDraft;
  for (const { name } of LIMITS) out[name] = String(stored?.[name] ?? effective[name]);
  return out;
}

export type LimitCheck = { ok: true; limits: Record<LimitName, number> } | { ok: false; problems: Partial<Record<LimitName, number>> };

/** The limits of the text, or the fields out of range with their largest value. */
export function limitsOfDraft(draft: LimitDraft): LimitCheck {
  const limits = {} as Record<LimitName, number>;
  const problems: Partial<Record<LimitName, number>> = {};
  for (const { name, max } of LIMITS) {
    const text = draft[name].trim();
    if (!/^\d{1,6}$/.test(text) || Number(text) > max) problems[name] = max;
    else limits[name] = Number(text);
  }
  return Object.keys(problems).length > 0 ? { ok: false, problems } : { ok: true, limits };
}
