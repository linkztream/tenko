// The list of trusted relay agents of the DHCP server settings: the text of the form (one prefix
// per line) to the list the server takes, and the other way. A bare address means the host
// prefix (/32 or /128); a prefix with host bits is refused, the way the server refuses it.
import { formatCidr, parseCidr } from "../../ipam/ip";

export const MAX_TRUSTED_RELAYS = 256;

export type RelayCheck =
  | { ok: true; list: string[] }
  | { ok: false; problem: "format" | "host_bits" | "count"; line?: number; text?: string };

/** The prefix of one line, or why it is not one. */
export function relayPrefix(text: string): { ok: true; prefix: string } | { ok: false; problem: "format" | "host_bits" } {
  const strict = parseCidr(text);
  if (strict !== null) return { ok: true, prefix: formatCidr(strict) };
  return { ok: false, problem: parseCidr(text, { strict: false }) !== null ? "host_bits" : "format" };
}

/** The list of the lines of the text: blank lines are skipped, duplicates are kept once. */
export function relayList(text: string): RelayCheck {
  const list: string[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (line === "") continue;
    const one = relayPrefix(line);
    if (!one.ok) return { ok: false, problem: one.problem, line: i + 1, text: line };
    if (!list.includes(one.prefix)) list.push(one.prefix);
  }
  if (list.length > MAX_TRUSTED_RELAYS) return { ok: false, problem: "count" };
  return { ok: true, list };
}

/** The host prefix of an address: `192.0.2.1` is `192.0.2.1/32`. */
export function hostPrefix(address: string): string {
  return address.includes("/") ? address : `${address}${address.includes(":") ? "/128" : "/32"}`;
}
