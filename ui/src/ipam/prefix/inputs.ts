// What the prefix and range forms check before anything is sent: the network text, the alarm
// thresholds and the lease time. Pure functions, so the rules can be tested without a form.
import type { UtilizationAlarm } from "../../api/types";
import { containsIp, formatCidr, parseCidr, parseIp, type Cidr } from "../ip";

export type NetworkCheck =
  | { ok: true; cidr: Cidr }
  | { ok: false; reason: "empty" | "invalid" }
  | { ok: false; reason: "host_bits"; given: string; network: string };

/** Checks the text of a network: CIDR form, no host bits. A host bits mistake comes with the fix. */
export function checkNetwork(text: string): NetworkCheck {
  const given = text.trim();
  if (given === "") return { ok: false, reason: "empty" };
  if (!given.includes("/")) return { ok: false, reason: "invalid" };
  const strict = parseCidr(given);
  if (strict) return { ok: true, cidr: strict };
  const loose = parseCidr(given, { strict: false });
  if (loose) return { ok: false, reason: "host_bits", given, network: formatCidr(loose) };
  return { ok: false, reason: "invalid" };
}

/**
 * The part of a parent network that every child shares, as far as it can be typed on a group
 * boundary: "203.0.113." for 203.0.113.0/24 and "2001:db8:" for 2001:db8::/32. The person
 * continues from there. Nothing for a parent that does not parse or is too short.
 */
export function networkHint(parentCidr: string | undefined): string {
  if (!parentCidr) return "";
  const parent = parseCidr(parentCidr);
  if (!parent) return "";
  if (parent.version === 4) {
    const octets = Math.floor(parent.length / 8);
    if (octets === 0) return "";
    const out: string[] = [];
    for (let i = 0; i < octets; i++) out.push(String(Number((parent.network >> BigInt(24 - i * 8)) & 0xffn)));
    return `${out.join(".")}.`;
  }
  const groups = Math.floor(parent.length / 16);
  if (groups === 0) return "";
  const out: string[] = [];
  for (let i = 0; i < groups; i++) out.push(((parent.network >> BigInt(112 - i * 16)) & 0xffffn).toString(16));
  return `${out.join(":")}:`;
}

export type AlarmCheck =
  | { ok: true; alarm: UtilizationAlarm | null }
  | { ok: false; warn?: "required" | "range" | "order"; crit?: "required" | "range" | "order" };

function percent(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,3}$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return value >= 1 && value <= 100 ? value : null;
}

/** Both thresholds empty is no alarm; otherwise both are 1 to 100 and warning is below critical. */
export function checkAlarm(warn: string, crit: string): AlarmCheck {
  const w = warn.trim();
  const c = crit.trim();
  if (w === "" && c === "") return { ok: true, alarm: null };
  const problems: { warn?: "required" | "range" | "order"; crit?: "required" | "range" | "order" } = {};
  const warnValue = percent(w);
  const critValue = percent(c);
  if (w === "") problems.warn = "required";
  else if (warnValue === null) problems.warn = "range";
  if (c === "") problems.crit = "required";
  else if (critValue === null) problems.crit = "range";
  if (warnValue !== null && critValue !== null && warnValue >= critValue) problems.crit = "order";
  if (problems.warn || problems.crit) return { ok: false, ...problems };
  return { ok: true, alarm: { warn_pct: warnValue as number, crit_pct: critValue as number } };
}

/** Whether `text` is an address of the family of `cidr` that lies inside it. */
export function addressIn(cidr: Cidr, text: string): "ok" | "invalid" | "outside" {
  const ip = parseIp(text);
  if (!ip) return "invalid";
  return containsIp(cidr, ip) ? "ok" : "outside";
}
