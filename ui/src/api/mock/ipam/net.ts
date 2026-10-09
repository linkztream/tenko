// Address helpers of the IPAM mock on top of the arithmetic library (src/ipam/ip.ts): the
// parsed form of stored text, the assignable bounds of a network and a few counting
// functions. Stored objects keep addresses and prefixes as text, like the API shows them.
import { firstOf, formatIp, lastOf, parseCidr, parseIp, type Cidr, type Ip, type IpVersion } from "../../../ipam/ip";

const cidrCache = new Map<string, Cidr>();
const ipCache = new Map<string, Ip>();

/** The parsed form of a stored prefix; stored text is always valid. */
export function cidrOf(text: string): Cidr {
  let found = cidrCache.get(text);
  if (!found) {
    const parsed = parseCidr(text);
    if (!parsed) throw new Error(`the stored prefix ${text} is not valid`);
    if (cidrCache.size > 5000) cidrCache.clear();
    cidrCache.set(text, parsed);
    found = parsed;
  }
  return found;
}

/** The parsed form of a stored address; stored text is always valid. */
export function ipOf(text: string): Ip {
  let found = ipCache.get(text);
  if (!found) {
    const parsed = parseIp(text);
    if (!parsed) throw new Error(`the stored address ${text} is not valid`);
    if (ipCache.size > 5000) ipCache.clear();
    ipCache.set(text, parsed);
    found = parsed;
  }
  return found;
}

export function ipText(version: IpVersion, value: bigint): string {
  return formatIp({ version, value });
}

/** Number of values from `first` to `last`, both included. */
export function span(first: bigint, last: bigint): bigint {
  return last >= first ? last - first + 1n : 0n;
}

/**
 * The assignable addresses of a network like the server counts them: IPv4 without the
 * network and broadcast address (prefix lengths up to 30), IPv6 without the subnet-router
 * anycast address (lengths up to 126).
 */
export function hostBounds(cidr: Cidr): { first: bigint; last: bigint } {
  const first = firstOf(cidr).value;
  const last = lastOf(cidr).value;
  if (cidr.version === 4 && cidr.length <= 30) return { first: first + 1n, last: last - 1n };
  if (cidr.version === 6 && cidr.length <= 126) return { first: first + 1n, last };
  return { first, last };
}

/** Number of assignable addresses of a network. */
export function hostCapacity(cidr: Cidr): bigint {
  const { first, last } = hostBounds(cidr);
  return span(first, last);
}

/** The first and last value of a prefix. */
export function bounds(cidr: Cidr): { first: bigint; last: bigint } {
  return { first: firstOf(cidr).value, last: lastOf(cidr).value };
}

/** `used + reserved` in tenths of a percent of the capacity, rounded, at most 1000. */
export function permille(used: bigint, reserved: bigint, capacity: bigint): number {
  if (capacity === 0n) return 0;
  const scaled = ((used + reserved) * 2000n + capacity) / (2n * capacity);
  return Number(scaled > 1000n ? 1000n : scaled);
}
