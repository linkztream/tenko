// Client-side checks of the wizard's text fields. They only spare the operator a round trip;
// the server checks everything again (`auth.setup.invalid_host_name`, `auth.invalid_request`).

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);
const HEXTET = /^[0-9a-f]{1,4}$/i;

/** A dotted-quad IPv4 address; octets have no leading zeros. */
export function isIPv4(text: string): boolean {
  return IPV4.test(text);
}

/** An IPv6 address in any of its text forms (compressed, with an embedded IPv4 tail), no zone id. */
export function isIPv6(text: string): boolean {
  if (!text.includes(":") || !/^[0-9a-f:.]+$/i.test(text) || text.includes(":::")) return false;
  let body = text;
  const lastColon = body.lastIndexOf(":");
  const tail = body.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isIPv4(tail)) return false;
    // An embedded IPv4 address stands for the last two groups.
    body = `${body.slice(0, lastColon + 1)}0:0`;
  }
  const halves = body.split("::");
  if (halves.length > 2) return false;
  const groups = (part: string): string[] | null => {
    if (part === "") return [];
    const list = part.split(":");
    return list.every((g) => HEXTET.test(g)) ? list : null;
  };
  if (halves.length === 2) {
    const left = groups(halves[0] ?? "");
    const right = groups(halves[1] ?? "");
    return left !== null && right !== null && left.length + right.length <= 7;
  }
  const all = groups(body);
  return all !== null && all.length === 8;
}

/** An IPv4 or IPv6 address, or a prefix: `192.0.2.10`, `198.51.100.0/24`, `2001:db8::/32`. */
export function isAddressOrPrefix(entry: string): boolean {
  const slash = entry.indexOf("/");
  const address = slash < 0 ? entry : entry.slice(0, slash);
  const v4 = isIPv4(address);
  if (!v4 && !isIPv6(address)) return false;
  if (slash < 0) return true;
  const length = entry.slice(slash + 1);
  if (!/^\d{1,3}$/.test(length)) return false;
  return Number(length) <= (v4 ? 32 : 128);
}

export type HostNameProblem = "empty" | "address" | "chars" | "length";

export type HostNameCheck = { ok: true; name: string } | { ok: false; problem: HostNameProblem };

const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * The host name is the name in the TLS certificate and the WebAuthn relying-party id
 * (plan Q5), so it must be a DNS name and never an address. Returns the normalized name
 * (lower case, no trailing dot).
 */
export function validateHostName(raw: string): HostNameCheck {
  const trimmed = raw.trim();
  if (trimmed === "") return { ok: false, problem: "empty" };
  const bare = trimmed.replace(/^\[/, "").replace(/\]$/, "");
  if (bare.includes(":") || isIPv4(bare)) return { ok: false, problem: "address" };
  const name = trimmed.toLowerCase().replace(/\.$/, "");
  if (name === "") return { ok: false, problem: "empty" };
  if (name.length > 253) return { ok: false, problem: "length" };
  const labels = name.split(".");
  if (labels.some((l) => l.length > 63)) return { ok: false, problem: "length" };
  if (!labels.every((l) => LABEL.test(l))) return { ok: false, problem: "chars" };
  // Digits and dots only is read as an address by browsers.
  if (labels.every((l) => /^\d+$/.test(l))) return { ok: false, problem: "address" };
  return { ok: true, name };
}

export interface ProxyList {
  /** Every entry, in the order typed, without duplicates. */
  entries: string[];
  /** The entries that are neither an address nor a prefix. */
  invalid: string[];
}

/** Trusted proxies: addresses or prefixes separated by new lines (commas and spaces are accepted too). */
export function parseProxyList(raw: string): ProxyList {
  const entries = Array.from(new Set(raw.split(/[\s,;]+/).filter((e) => e.length > 0)));
  return { entries, invalid: entries.filter((e) => !isAddressOrPrefix(e)) };
}

/** Lower-case letter first, then letters, digits, dot, dash or underscore: 3 to 31 characters. */
export const USER_NAME_PATTERN = /^[a-z][a-z0-9._-]{2,30}$/;

export function isValidUserName(raw: string): boolean {
  return USER_NAME_PATTERN.test(raw.trim());
}
