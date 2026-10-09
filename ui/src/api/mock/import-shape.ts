// Value shapes and the lenient parsers behind them (crates/tenko-ipam/src/import/shape.rs).
// The mapping step counts, for every column, how many values look like an address, a network,
// a range, a MAC address, a DUID, a number or text; translation uses the same parsers, so a
// value that is counted as an address is also imported as one.
import { formatIp, parseIp, type Ip } from "../../ipam/ip";

export type Shape = "empty" | "address" | "cidr" | "range" | "mac" | "duid" | "number" | "text";

/** How many values of a column have each shape (the `ShapeCounts` schema). */
export interface ShapeCounts {
  empty: number;
  address: number;
  cidr: number;
  range: number;
  mac: number;
  duid: number;
  number: number;
  text: number;
}

export function emptyCounts(): ShapeCounts {
  return { empty: 0, address: 0, cidr: 0, range: 0, mac: 0, duid: 0, number: 0, text: 0 };
}

/** Values that are not empty. */
export function filled(counts: ShapeCounts): number {
  return counts.address + counts.cidr + counts.range + counts.mac + counts.duid + counts.number + counts.text;
}

/**
 * The shape of at least `percent` of the non-empty values, if any. Addresses and ranges
 * count together as addresses (a range cell in an address column).
 */
export function dominant(counts: ShapeCounts, percent: number): Shape | null {
  const total = filled(counts);
  if (total === 0) return null;
  const candidates: [Shape, number][] = [
    ["address", counts.address + counts.range],
    ["cidr", counts.cidr],
    ["mac", counts.mac],
    ["duid", counts.duid],
    ["number", counts.number],
    ["text", counts.text],
  ];
  return candidates.find(([, count]) => count * 100 >= total * percent)?.[0] ?? null;
}

const MAX_DUID_OCTETS = 130;

/** One decimal octet of one to three digits (leading zeros allowed, read as decimal). */
function parseOctet(part: string): number | null {
  if (!/^[0-9]{1,3}$/.test(part)) return null;
  const value = Number(part);
  return value <= 255 ? value : null;
}

/** A dotted-quad IPv4 address; leading zeros are allowed. */
function parseIpv4(text: string): Ip | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    const octet = parseOctet(part);
    if (octet === null) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return { version: 4, value };
}

/** An address leniently: IPv4 with leading zeros, IPv6 in any standard form and in brackets. */
export function parseAddress(value: string): Ip | null {
  const text = value.trim();
  if (text.includes(":")) {
    const inner = text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1) : text;
    const ip = parseIp(inner);
    return ip?.version === 6 ? ip : null;
  }
  return parseIpv4(text);
}

function parseLength(text: string, v6: boolean): number | null {
  if (!/^[0-9]{1,3}$/.test(text)) return null;
  const length = Number(text);
  return length <= (v6 ? 128 : 32) ? length : null;
}

/** The prefix length of a contiguous netmask, null for a mask with holes. */
function maskLength(mask: Ip): number | null {
  const bits = Number(mask.value);
  let ones = 0;
  while (ones < 32 && (bits >>> (31 - ones)) & 1) ones += 1;
  const rest = ones === 32 ? 0 : (bits << ones) >>> 0;
  return rest === 0 ? ones : null;
}

export interface LooseCidr {
  ip: Ip;
  length: number;
}

/**
 * A network or an address with a prefix length: `192.0.2.0/24`, `192.0.2.5/24` (host bits
 * kept, the caller decides), `192.0.2.0/255.255.255.0` (a contiguous mask), `2001:db8::/32`.
 */
export function parseCidrLoose(value: string): LooseCidr | null {
  const text = value.trim();
  const slash = text.indexOf("/");
  if (slash < 0) return null;
  const ip = parseAddress(text.slice(0, slash));
  if (!ip) return null;
  const rest = text.slice(slash + 1).trim();
  let length: number | null;
  if (ip.version === 4 && rest.includes(".")) {
    const mask = parseIpv4(rest);
    length = mask ? maskLength(mask) : null;
  } else {
    length = parseLength(rest, ip.version === 6);
  }
  return length === null ? null : { ip, length };
}

/** The network address of an address and a length. */
export function networkOf(ip: Ip, length: number): Ip {
  const bits = ip.version === 4 ? 32 : 128;
  const hostBits = BigInt(bits - length);
  return { version: ip.version, value: (ip.value >> hostBits) << hostBits };
}

export function sameIp(a: Ip, b: Ip): boolean {
  return a.version === b.version && a.value === b.value;
}

export interface AddressRange {
  first: Ip;
  last: Ip;
}

/**
 * An address range, ascending, of one family: `192.0.2.10-20` (last octet shorthand),
 * `192.0.2.10-192.0.2.20`, `192.0.2.10 - 192.0.2.20`, `2001:db8::10-2001:db8::1f`.
 */
export function parseRange(value: string): AddressRange | null {
  const text = value.trim();
  const dash = text.indexOf("-");
  if (dash < 0) return null;
  const lastText = text.slice(dash + 1).trim();
  if (lastText.includes("-")) return null;
  const first = parseAddress(text.slice(0, dash));
  if (!first) return null;
  let last: Ip | null;
  if (first.version === 4 && !lastText.includes(".") && !lastText.includes(":")) {
    const octet = parseOctet(lastText);
    last = octet === null ? null : { version: 4, value: (first.value & ~0xffn) | BigInt(octet) };
  } else {
    last = parseAddress(lastText);
  }
  if (!last || last.version !== first.version || first.value > last.value) return null;
  return { first, last };
}

/** A subnet mask (`255.255.255.0`) or prefix length (`24`, `/24`) as a prefix length. */
export function parseMask(value: string, v6: boolean): number | null {
  let text = value.trim();
  if (text.startsWith("/")) text = text.slice(1).trim();
  if (text.includes(".")) {
    if (v6) return null;
    const mask = parseIpv4(text);
    return mask ? maskLength(mask) : null;
  }
  return parseLength(text, v6);
}

function separatorOf(value: string): string | null {
  if (value.includes(":")) return ":";
  if (value.includes("-")) return "-";
  return null;
}

/** The bytes of hexadecimal groups, or null when a digit is not hexadecimal or the count is odd. */
function decodeHex(groups: readonly string[]): number[] | null {
  const digits = groups.join("");
  if (!/^[0-9a-fA-F]*$/.test(digits) || digits.length % 2 !== 0) return null;
  const bytes: number[] = [];
  for (let i = 0; i < digits.length; i += 2) bytes.push(parseInt(digits.slice(i, i + 2), 16));
  return bytes;
}

function hex(bytes: readonly number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
}

/**
 * A MAC address in colon, hyphen, Cisco dot or plain hexadecimal notation, any case, as
 * `00:00:5e:00:53:01`. Plain digits without separators or hexadecimal letters are not a MAC.
 */
export function parseMac(value: string): string | null {
  const text = value.trim();
  let bytes: number[] | null;
  const separator = separatorOf(text);
  if (separator) {
    const groups = text.split(separator);
    bytes = groups.length === 6 && groups.every((g) => g.length === 2) ? decodeHex(groups) : null;
  } else if (text.includes(".")) {
    const groups = text.split(".");
    bytes = groups.length === 3 && groups.every((g) => g.length === 4) ? decodeHex(groups) : null;
  } else {
    bytes = text.length === 12 && /[a-zA-Z]/.test(text) ? decodeHex([text]) : null;
  }
  return bytes?.length === 6 ? hex(bytes) : null;
}

/** A DHCPv6 DUID: hexadecimal octets (`:` or `-` separated, or none), 7 to 130 of them. */
export function parseDuid(value: string): string | null {
  const text = value.trim();
  const separator = separatorOf(text);
  let bytes: number[] | null;
  if (separator) {
    const groups = text.split(separator);
    bytes = groups.every((g) => g.length === 2) ? decodeHex(groups) : null;
  } else {
    bytes = decodeHex([text]);
  }
  if (!bytes || bytes.length <= 6 || bytes.length > MAX_DUID_OCTETS) return null;
  return hex(bytes);
}

/** Eight colon-separated groups of two hexadecimal digits: a DUID, although it reads as IPv6. */
function isEightOctets(value: string): boolean {
  const groups = value.split(":");
  return groups.length === 8 && groups.every((g) => /^[0-9a-fA-F]{2}$/.test(g));
}

/** An integer or a decimal with a point or a comma. */
function isNumber(value: string): boolean {
  const rest = value.replace(/^[+-]/, "");
  if (rest.includes(",")) return /^[0-9]+,[0-9]+$/.test(rest);
  return /^([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$/.test(rest);
}

/**
 * The shape of a value. The checks run in this order: empty, address, network, range, MAC,
 * DUID, number, text. A netmask is an address (headers tell masks apart); plain digits are a
 * number, never a DUID or a MAC.
 */
export function shapeOf(value: string): Shape {
  const text = value.trim();
  if (text === "") return "empty";
  if (!isEightOctets(text) && parseAddress(text)) return "address";
  if (parseCidrLoose(text)) return "cidr";
  if (parseRange(text)) return "range";
  if (parseMac(text)) return "mac";
  if (!/^[0-9]+$/.test(text) && parseDuid(text)) return "duid";
  if (isNumber(text)) return "number";
  return "text";
}

/** The address as text (IPv6 in canonical form). */
export function ipText(ip: Ip): string {
  return formatIp(ip);
}
