// IP address and prefix arithmetic shared by the IPAM views and the mock API. Pure
// functions on plain values, no dependencies and no DOM access. Addresses are bigint
// values, so IPv4 (32 bits) and IPv6 (128 bits) share one code path.

export type IpVersion = 4 | 6;

export interface Ip {
  readonly version: IpVersion;
  readonly value: bigint;
}

/** A prefix. `network` has all host bits zero. */
export interface Cidr {
  readonly version: IpVersion;
  readonly network: bigint;
  readonly length: number;
}

export function bitsOf(version: IpVersion): 32 | 128 {
  return version === 4 ? 32 : 128;
}

/** The largest value of the version (all bits set). */
function maxValue(version: IpVersion): bigint {
  return (1n << BigInt(bitsOf(version))) - 1n;
}

/** The mask of the host bits of a prefix of the given length. */
function hostMask(version: IpVersion, length: number): bigint {
  return (1n << BigInt(bitsOf(version) - length)) - 1n;
}

function validLength(version: IpVersion, length: number): boolean {
  return Number.isInteger(length) && length >= 0 && length <= bitsOf(version);
}

function parseIpv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseIpv6(text: string): bigint | null {
  let s = text;
  const lastColon = s.lastIndexOf(":");
  if (lastColon < 0) return null;

  // An embedded IPv4 tail stands for the last two groups.
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIpv4(tail);
    if (v4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }

  const dbl = s.indexOf("::");
  if (dbl !== s.lastIndexOf("::")) return null;

  let groups: string[];
  if (dbl < 0) {
    groups = s.split(":");
    if (groups.length !== 8) return null;
  } else {
    const before = s.slice(0, dbl);
    const after = s.slice(dbl + 2);
    const head = before === "" ? [] : before.split(":");
    const rest = after === "" ? [] : after.split(":");
    if (head.length + rest.length > 7) return null;
    groups = [...head, ...new Array<string>(8 - head.length - rest.length).fill("0"), ...rest];
  }

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    value = (value << 16n) | BigInt(`0x${group}`);
  }
  return value;
}

/**
 * Strict parse: IPv4 dotted quad (0-255, no leading zeros except "0"), IPv6 in full or
 * compressed form, case-insensitive, optionally with an embedded IPv4 tail
 * (::ffff:192.0.2.1). No zone ids and no brackets. Leading and trailing spaces are
 * trimmed. Returns null for anything else.
 */
export function parseIp(text: string): Ip | null {
  const s = text.trim();
  if (s.includes(":")) {
    const value = parseIpv6(s);
    return value === null ? null : { version: 6, value };
  }
  const value = parseIpv4(s);
  return value === null ? null : { version: 4, value };
}

function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));

  // Longest run of zero groups; the first one wins a tie.
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  let runLen = 0;
  groups.forEach((group, i) => {
    if (group !== 0) {
      runLen = 0;
      return;
    }
    if (runLen === 0) runStart = i;
    runLen++;
    if (runLen > bestLen) {
      bestStart = runStart;
      bestLen = runLen;
    }
  });

  const hex = (group: number) => group.toString(16);
  if (bestLen < 2) return groups.map(hex).join(":");
  const head = groups.slice(0, bestStart).map(hex).join(":");
  const rest = groups.slice(bestStart + bestLen).map(hex).join(":");
  return `${head}::${rest}`;
}

/**
 * IPv4 dotted quad; IPv6 in RFC 5952 canonical form (lowercase, no leading zeros, the
 * longest run of two or more zero groups compressed to "::", the first one on a tie; a
 * single zero group is not compressed; no embedded IPv4 form).
 */
export function formatIp(ip: Ip): string {
  if (ip.version === 6) return formatIpv6(ip.value);
  const v = ip.value;
  return [24n, 16n, 8n, 0n].map((shift) => String(Number((v >> shift) & 0xffn))).join(".");
}

/**
 * "192.0.2.0/24" or "2001:db8::/32". With strict (default true) host bits must be zero,
 * else null. Without strict the host bits are masked off. A missing "/len" means a host
 * prefix (/32 or /128). The length must be within 0..bits.
 */
export function parseCidr(text: string, options?: { strict?: boolean }): Cidr | null {
  const strict = options?.strict ?? true;
  const parts = text.trim().split("/");
  if (parts.length > 2) return null;
  const ip = parseIp(parts[0] ?? "");
  if (ip === null) return null;

  let length: number = bitsOf(ip.version);
  if (parts.length === 2) {
    const lenText = parts[1] ?? "";
    if (!/^(0|[1-9][0-9]{0,2})$/.test(lenText)) return null;
    length = Number(lenText);
    if (!validLength(ip.version, length)) return null;
  }

  const network = ip.value & ~hostMask(ip.version, length);
  if (strict && network !== ip.value) return null;
  return { version: ip.version, network, length };
}

export function formatCidr(c: Cidr): string {
  return `${formatIp({ version: c.version, value: c.network })}/${c.length}`;
}

/**
 * The prefix of the given length that holds `ip` (the host bits are masked off). Throws a
 * RangeError for a length outside 0..bits.
 */
export function cidrOf(ip: Ip, length: number): Cidr {
  if (!validLength(ip.version, length)) {
    throw new RangeError(`Prefix length ${length} is outside 0..${bitsOf(ip.version)}`);
  }
  return { version: ip.version, network: ip.value & ~hostMask(ip.version, length), length };
}

/** The number of addresses in the prefix: 2^(bits - length). */
export function sizeOf(c: Cidr): bigint {
  return 1n << BigInt(bitsOf(c.version) - c.length);
}

/** The network address. */
export function firstOf(c: Cidr): Ip {
  return { version: c.version, value: c.network };
}

/** The broadcast (IPv4) or last address of the prefix. */
export function lastOf(c: Cidr): Ip {
  return { version: c.version, value: c.network | hostMask(c.version, c.length) };
}

/**
 * The addresses a host may use: IPv4 networks with length <= 30 exclude the network and
 * broadcast address; IPv4 /31 and /32 and every IPv6 prefix use all addresses.
 */
export function usableRange(c: Cidr): { first: Ip; last: Ip } {
  const first = firstOf(c);
  const last = lastOf(c);
  if (c.version === 4 && c.length <= 30) {
    return {
      first: { version: 4, value: first.value + 1n },
      last: { version: 4, value: last.value - 1n },
    };
  }
  return { first, last };
}

/** The number of addresses in `usableRange`. */
export function usableCount(c: Cidr): bigint {
  return c.version === 4 && c.length <= 30 ? sizeOf(c) - 2n : sizeOf(c);
}

/** False across versions. */
export function containsIp(c: Cidr, ip: Ip): boolean {
  return c.version === ip.version && ip.value >= c.network && ip.value <= lastOf(c).value;
}

/** True when `inner` is equal to `outer` or more specific and inside it. */
export function containsCidr(outer: Cidr, inner: Cidr): boolean {
  return outer.version === inner.version && inner.length >= outer.length && containsIp(outer, firstOf(inner));
}

/** True when the two prefixes share at least one address. */
export function overlaps(a: Cidr, b: Cidr): boolean {
  return a.version === b.version && a.network <= lastOf(b).value && b.network <= lastOf(a).value;
}

/** Orders by version (IPv4 first), then by value. */
export function compareIp(a: Ip, b: Ip): -1 | 0 | 1 {
  if (a.version !== b.version) return a.version < b.version ? -1 : 1;
  if (a.value === b.value) return 0;
  return a.value < b.value ? -1 : 1;
}

/** Orders by version, then network, then shorter length first. */
export function compareCidr(a: Cidr, b: Cidr): -1 | 0 | 1 {
  if (a.version !== b.version) return a.version < b.version ? -1 : 1;
  if (a.network !== b.network) return a.network < b.network ? -1 : 1;
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

/** The address `delta` steps away, or null when that leaves the address space. */
export function addToIp(ip: Ip, delta: bigint): Ip | null {
  const value = ip.value + delta;
  if (value < 0n || value > maxValue(ip.version)) return null;
  return { version: ip.version, value };
}

/** Offset of `ip` inside `c` (ip - network), or null when outside. */
export function hostPart(c: Cidr, ip: Ip): bigint | null {
  return containsIp(c, ip) ? ip.value - c.network : null;
}

/** The address with the given offset inside `c`, or null when the offset is outside 0..size-1. */
export function withHostPart(c: Cidr, offset: bigint): Ip | null {
  if (offset < 0n || offset >= sizeOf(c)) return null;
  return { version: c.version, value: c.network + offset };
}

/** Number of addresses from first to last inclusive (0 when last < first or the versions differ). */
export function rangeSize(first: Ip, last: Ip): bigint {
  if (first.version !== last.version || last.value < first.value) return 0n;
  return last.value - first.value + 1n;
}

/** IPv6 prefixes whose length is a multiple of 4 (IPAM-06); IPv4 always true. */
export function isNibbleAligned(c: Cidr): boolean {
  return c.version === 4 || c.length % 4 === 0;
}

/**
 * A string that sorts addresses correctly with plain string comparison: "4:" or "6:"
 * followed by the value as fixed-width lowercase hex.
 */
export function ipSortKey(ip: Ip): string {
  return `${ip.version}:${ip.value.toString(16).padStart(bitsOf(ip.version) / 4, "0")}`;
}

/** An inclusive range of address values. */
interface Span {
  start: bigint;
  end: bigint;
}

/** The taken prefixes as sorted, merged spans clipped to the parent. */
function takenSpans(parent: Cidr, taken: readonly Cidr[]): Span[] {
  const parentLast = lastOf(parent).value;
  const spans: Span[] = [];
  for (const t of taken) {
    if (!overlaps(parent, t)) continue;
    const tLast = lastOf(t).value;
    spans.push({
      start: t.network < parent.network ? parent.network : t.network,
      end: tLast > parentLast ? parentLast : tLast,
    });
  }
  spans.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));

  const merged: Span[] = [];
  for (const span of spans) {
    const prev = merged[merged.length - 1];
    if (prev !== undefined && span.start <= prev.end + 1n) {
      if (span.end > prev.end) prev.end = span.end;
    } else {
      merged.push({ start: span.start, end: span.end });
    }
  }
  return merged;
}

/**
 * The child prefixes of `parent` with the given length that do not overlap any of
 * `taken`, in ascending order (or descending with `from: "highest"`), produced lazily.
 * Yields nothing when length < parent.length or length > bits. A candidate that overlaps
 * a taken prefix makes the search jump past that prefix, so a /32 parent with /64 children
 * never enumerates its 2^32 candidates. Entries of `taken` of the other version or outside
 * the parent are ignored.
 */
export function* freeSubnets(
  parent: Cidr,
  length: number,
  taken: readonly Cidr[],
  from: "lowest" | "highest" = "lowest",
): Generator<Cidr> {
  if (!Number.isInteger(length) || length < parent.length || length > bitsOf(parent.version)) return;

  const step = 1n << BigInt(bitsOf(parent.version) - length);
  const first = parent.network;
  const last = lastOf(parent).value;
  const spans = takenSpans(parent, taken);

  if (from === "lowest") {
    let candidate = first;
    let i = 0;
    while (candidate <= last) {
      while (i < spans.length && (spans[i]?.end ?? 0n) < candidate) i++;
      const span = spans[i];
      if (span !== undefined && span.start <= candidate + step - 1n) {
        // Continue with the first block that starts after the taken span.
        candidate = (span.end / step + 1n) * step;
        continue;
      }
      yield { version: parent.version, network: candidate, length };
      candidate += step;
    }
    return;
  }

  let candidate = last + 1n - step;
  let i = spans.length - 1;
  while (candidate >= first) {
    while (i >= 0 && (spans[i]?.start ?? 0n) > candidate + step - 1n) i--;
    const span = spans[i];
    if (span !== undefined && span.end >= candidate) {
      // Continue with the last block that ends before the taken span.
      candidate = (span.start / step) * step - step;
      continue;
    }
    yield { version: parent.version, network: candidate, length };
    candidate -= step;
  }
}

/** Parse then format, or the input unchanged when it does not parse. */
export function normalizeIp(text: string): string {
  const ip = parseIp(text);
  return ip === null ? text : formatIp(ip);
}

/** Parse (strict) then format, or the input unchanged when it does not parse. */
export function normalizeCidr(text: string): string {
  const cidr = parseCidr(text);
  return cidr === null ? text : formatCidr(cidr);
}
