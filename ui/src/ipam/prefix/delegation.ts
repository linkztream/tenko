// The rules of a delegation pool (docs/dhcp.md section 19.10): the length of the prefixes it hands
// to requesting routers and the boundaries its first and last address lie on. The server checks
// them again; these functions let a form say what is wrong before anything is sent.
import type { Range } from "../../api/types";
import { t } from "../../i18n";
import { parseIp } from "../ip";

/** The longest prefix a router is given: a /64, so SLAAC still works on its links. */
export const MAX_DELEGATED_LEN = 64;

export type DelegatedCheck = { ok: true; len: number } | { ok: false; reason: "required" | "number" | "range" };

/**
 * The delegated length of a text: a whole number longer than the length of the network and at
 * most 64. `networkLength` is null when the network is unknown; only the upper limit is checked then.
 */
export function checkDelegatedLen(text: string, networkLength: number | null): DelegatedCheck {
  const value = text.trim();
  if (value === "") return { ok: false, reason: "required" };
  if (!/^\d{1,3}$/.test(value)) return { ok: false, reason: "number" };
  const len = Number(value);
  if (len > MAX_DELEGATED_LEN || (networkLength !== null && len <= networkLength)) return { ok: false, reason: "range" };
  return { ok: true, len };
}

/** Whether an IPv6 address is the first (`end` "first") or the last (`end` "last") address of a /len prefix. */
export function onBoundary(address: string, len: number, end: "first" | "last"): boolean {
  const ip = parseIp(address);
  if (!ip || ip.version !== 6) return false;
  const host = (1n << BigInt(128 - len)) - 1n;
  const low = ip.value & host;
  return end === "first" ? low === 0n : low === host;
}

/** How many /len prefixes lie between two addresses on their boundaries, or null for a range that is not an ascending IPv6 one. */
export function delegatedPrefixCount(first: string, last: string, len: number): bigint | null {
  const a = parseIp(first);
  const b = parseIp(last);
  if (!a || !b || a.version !== 6 || b.version !== 6 || b.value < a.value || len < 1 || len > 128) return null;
  return (b.value - a.value + 1n) >> BigInt(128 - len);
}

/** What a delegation pool hands out, in words: `/60, 16 prefixes`. */
export function delegationWords(range: Pick<Range, "first" | "last" | "delegated_len">): string {
  const len = range.delegated_len;
  if (len === null || len === undefined) return "";
  const count = delegatedPrefixCount(range.first, range.last, len);
  if (count === null) return `/${len}`;
  const safe = BigInt(Number.MAX_SAFE_INTEGER);
  return t("ipam.range.delegation", { len, count: Number(count > safe ? safe : count) });
}
