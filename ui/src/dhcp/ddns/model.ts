// Pure helpers of the DDNS settings (docs/dhcp.md, section 13): the draft a form edits, the
// settings it stands for, the comparison that decides whether anything changed, the rule of the
// security profile for a zone, and the server's field errors by field. No DOM, no i18n: the words
// are in ../words.ts.
import type { Zone } from "../../dns/types";
import type { DdnsPolicy } from "../types";

export type DdnsConflict = NonNullable<DdnsPolicy["conflict"]>;
export type Profile = "home" | "standard" | "hardened" | "lab";

/** The largest TTL the form accepts; the server still refuses more than a week. */
export const TTL_MAX = 2_147_483_647;

/** The DDNS settings as a form holds them: texts for the zone and the TTL, the switches as they are. */
export interface DdnsDraft {
  enabled: boolean;
  /** The forward zone identifier; empty: the zone of the scope's domain name. */
  zone: string;
  reverse: boolean;
  /** The TTL in seconds as typed; empty: a third of the lease time. */
  ttl: string;
  conflict: DdnsConflict;
  clientMayUpdateA: boolean;
  legacyClients: boolean;
  refuseForeign: boolean;
}

/** The fields of the settings a server error can name. */
export type DdnsField = "enabled" | "forward_zone" | "reverse" | "ttl" | "conflict" | "client_may_update_a" | "legacy_clients" | "refuse_foreign";

/** The draft of settings; absent fields read as the model's defaults (off, PTR on, protect, legacy clients on). */
export function draftOfDdns(ddns?: DdnsPolicy | null): DdnsDraft {
  return {
    enabled: ddns?.enabled ?? false,
    zone: ddns?.forward_zone ?? "",
    reverse: ddns?.reverse ?? true,
    ttl: ddns?.ttl === undefined || ddns.ttl === null ? "" : String(ddns.ttl),
    conflict: ddns?.conflict ?? "protect",
    clientMayUpdateA: ddns?.client_may_update_a ?? false,
    legacyClients: ddns?.legacy_clients ?? true,
    refuseForeign: ddns?.refuse_foreign ?? false,
  };
}

/** The settings of a draft in the form the API takes (every switch explicit, zone and TTL only when set), or what is wrong. */
export function ddnsOfDraft(draft: DdnsDraft): { ok: true; ddns: DdnsPolicy } | { ok: false; field: "ttl"; problem: "ttl" } {
  const text = draft.ttl.trim();
  let ttl: number | undefined;
  if (text !== "") {
    ttl = /^\d{1,10}$/.test(text) ? Number(text) : Number.NaN;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > TTL_MAX) return { ok: false, field: "ttl", problem: "ttl" };
  }
  const ddns: DdnsPolicy = {
    enabled: draft.enabled,
    reverse: draft.reverse,
    conflict: draft.conflict,
    client_may_update_a: draft.clientMayUpdateA,
    legacy_clients: draft.legacyClients,
    refuse_foreign: draft.refuseForeign,
  };
  if (draft.zone !== "") ddns.forward_zone = draft.zone;
  if (ttl !== undefined) ddns.ttl = ttl;
  return { ok: true, ddns };
}

/** The settings with every default written out, so that two settings compare by meaning. */
export function normalizedDdns(ddns?: DdnsPolicy | null): DdnsPolicy {
  const out = ddnsOfDraft(draftOfDdns(ddns));
  return out.ok ? out.ddns : { ...(ddns ?? {}) };
}

/** Whether two settings mean the same (an absent field and its default are equal). */
export function sameDdns(a?: DdnsPolicy | null, b?: DdnsPolicy | null): boolean {
  return JSON.stringify(normalizedDdns(a)) === JSON.stringify(normalizedDdns(b));
}

/**
 * The errors of a refused request by field of the settings: a server field `ddns.ttl` (prefix
 * `ddns`) or `action.ddns.ttl` (prefix `action.ddns`) is the field `ttl`.
 */
export function ddnsFieldErrors(fields: Readonly<Record<string, string>>, prefix: string): Partial<Record<DdnsField, string>> {
  const out: Partial<Record<DdnsField, string>> = {};
  for (const [key, message] of Object.entries(fields)) {
    if (key === prefix || !key.startsWith(`${prefix}.`)) continue;
    out[key.slice(prefix.length + 1) as DdnsField] = message;
  }
  return out;
}

/** Whether a refusal names the settings (`ddns` or `ddns.ttl`). */
export function namesDdns(fields: Readonly<Record<string, string>>, prefix: string): boolean {
  return Object.keys(fields).some((key) => key === prefix || key.startsWith(`${prefix}.`));
}

/** The zones a forward zone can be: primary zones that are not a reverse zone. */
export function isForwardZone(zone: Pick<Zone, "kind" | "name" | "reverse_of">): boolean {
  return zone.kind === "primary" && !zone.reverse_of && !/\.(in-addr|ip6)\.arpa\.?$/i.test(zone.name);
}

/** Home and Lab let a zone take DHCP updates unless it says otherwise; Standard and Hardened only a zone that says so. */
export function profileOpensZones(profile: Profile): boolean {
  return profile === "home" || profile === "lab";
}

export type ZoneDhcp = "on" | "off" | "profile_on" | "profile_off";

/** Whether a zone takes DHCP updates by its update policy (`dhcp` true, false, or unset: the profile decides). */
export function zoneTakesDhcp(update: { dhcp?: boolean | null } | undefined, profile: Profile): ZoneDhcp {
  if (update?.dhcp === true) return "on";
  if (update?.dhcp === false) return "off";
  return profileOpensZones(profile) ? "profile_on" : "profile_off";
}
