// The requests and pure helpers of the trust anchors and the negative trust anchors on the
// recursion page (WP10.4, recursion plan section 3.4): the anchors with their keys and RFC 5011
// states (`GET /dns/trust-anchors`), adding a key as a DS or a DNSKEY record (`POST`), removing a
// zone's anchor (`DELETE /dns/trust-anchors/{zone}`) and running RFC 5011 now (`POST .../refresh`);
// the negative trust anchors (`GET|POST /dns/ntas`, `DELETE /dns/ntas/{id}`). The root is written
// `root` in a path (a URL turns the segment `.` into a dot segment), a zone named `root` as `root.`.
// No translated text here.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { fetchAll } from "../../api/paginate";
import { canonical, validName } from "../model";

type S = components["schemas"];
export type TrustAnchorItem = S["TrustAnchorItem"];
export type AnchorKey = S["AnchorKey"];
export type AnchorState = S["AnchorState"];
export type NtaItem = S["NtaItem"];

/** The RFC 5011 states in the order a key goes through them. */
export const ANCHOR_STATES: readonly AnchorState[] = ["start", "add_pend", "valid", "missing", "revoked", "removed"];

/** The longest a negative trust anchor may live (RFC 7646 section 3: seven days). */
export const NTA_MAX_SECONDS = 7 * 24 * 3600;

/** The longest reason of a negative trust anchor. */
export const NTA_REASON_MAX = 500;

export async function listAnchors(signal?: AbortSignal): Promise<{ items: TrustAnchorItem[]; revision: number }> {
  const all = await fetchAll<TrustAnchorItem>("/api/v1/dns/trust-anchors", { signal });
  return { items: [...all.items].sort((a, b) => zoneOrder(a.zone, b.zone)), revision: Number(all.revision) };
}

export function addAnchor(body: S["TrustAnchorAdd"]): Promise<TrustAnchorItem> {
  return api.post("/api/v1/dns/trust-anchors", { body });
}

export async function removeAnchor(zone: string): Promise<void> {
  await api.delete("/api/v1/dns/trust-anchors/{zone}", { path: { zone: zoneSegment(zone) } });
}

export async function refreshAnchor(zone: string): Promise<void> {
  await api.post("/api/v1/dns/trust-anchors/{zone}/refresh", { path: { zone: zoneSegment(zone) } });
}

export async function listNtas(signal?: AbortSignal): Promise<{ items: NtaItem[]; revision: number }> {
  const all = await fetchAll<NtaItem>("/api/v1/dns/ntas", { signal });
  return { items: [...all.items].sort((a, b) => a.expires_at.localeCompare(b.expires_at) || zoneOrder(a.zone, b.zone)), revision: Number(all.revision) };
}

export function createNta(body: S["NtaCreate"]): Promise<NtaItem> {
  return api.post("/api/v1/dns/ntas", { body });
}

export async function deleteNta(id: string): Promise<void> {
  await api.delete("/api/v1/dns/ntas/{id}", { path: { id } });
}

/** The path segment of a zone: `root` for the root, `root.` for a zone named `root`. */
export function zoneSegment(zone: string): string {
  const name = canonical(zone);
  if (name === "." || name === "") return "root";
  return name === "root" ? "root." : name;
}

/** Whether a zone is the root. */
export function isRootZone(zone: string): boolean {
  const name = canonical(zone);
  return name === "." || name === "";
}

/** Zones from the root down, then by name. */
export function zoneOrder(a: string, b: string): number {
  if (isRootZone(a) !== isRootZone(b)) return isRootZone(a) ? -1 : 1;
  if (isRootZone(a)) return 0;
  const la = canonical(a).split(".").reverse();
  const lb = canonical(b).split(".").reverse();
  for (let i = 0; i < Math.min(la.length, lb.length); i += 1) {
    const x = la[i] as string;
    const y = lb[i] as string;
    if (x !== y) return x < y ? -1 : 1;
  }
  return la.length - lb.length;
}

/** A zone as the forms send it: `.` for the root, else the canonical name; null when it is not a name. */
export function zoneInput(typed: string): string | null {
  const name = canonical(typed.trim());
  if (name === "" || name === ".") return ".";
  return validName(name) && !name.includes("*") ? name : null;
}

/** The anchor's keys that the resolver trusts now (`valid`) and those on their way (`add_pend`). */
export function keyCounts(anchor: TrustAnchorItem): { valid: number; pending: number } {
  return {
    valid: anchor.keys.filter((k) => k.state === "valid").length,
    pending: anchor.keys.filter((k) => k.state === "add_pend").length,
  };
}

/** The shape a typed DS (`<key tag> <algorithm> <digest type> <hex digest>`) or DNSKEY record
 * (`<flags> <protocol> <algorithm> <base64 key>`) has; the server parses it again. */
export function keyShape(kind: "ds" | "dnskey", text: string): boolean {
  const parts = text.trim().split(/\s+/);
  if (parts.length < 4) return false;
  const [a, b, c] = parts as [string, string, string];
  if (![a, b, c].every((p) => /^\d{1,5}$/.test(p))) return false;
  const rest = parts.slice(3).join("");
  return kind === "ds" ? /^[0-9a-f]+$/i.test(rest) && rest.length % 2 === 0 : /^[A-Za-z0-9+/]+=*$/.test(rest);
}

/**
 * A negative trust anchor's lifetime as people write it (`30m`, `12h`, `2d`, `1d12h`, `90s`), in
 * seconds; null when it is not one, or 0 or more than seven days.
 */
export function parseLifetime(text: string): number | null {
  const typed = text.trim().toLowerCase();
  if (!/^(\d+[dhms])+$/.test(typed)) return null;
  const units: Record<string, number> = { d: 86_400, h: 3_600, m: 60, s: 1 };
  let seconds = 0;
  for (const [, count, unit] of typed.matchAll(/(\d+)([dhms])/g)) seconds += Number(count) * (units[unit as string] ?? 0);
  return seconds > 0 && seconds <= NTA_MAX_SECONDS ? seconds : null;
}

/** Whether a negative trust anchor's expiry has passed at `now` (the server removes it shortly after). */
export function ntaExpired(nta: Pick<NtaItem, "expires_at">, now: number): boolean {
  return new Date(nta.expires_at).getTime() <= now;
}
