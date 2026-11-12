// The list of trusted relay agents of the DHCP server settings: the text of the form (one relay per
// line, `RELAY = LINK, LINK`) to the list the server takes, and the other way. A bare address
// means the host prefix (/32 or /128); a prefix with host bits is refused, the way the server
// refuses it. The links are the networks the relay may name.
import { compareCidr, containsCidr, formatCidr, overlaps, parseCidr, type Cidr } from "../../ipam/ip";
import type { components } from "../../api/generated/schema";

export const MAX_TRUSTED_RELAYS = 256;
export const MAX_RELAY_LINKS = 64;

export type TrustedRelay = components["schemas"]["TrustedRelay"];

export type RelayProblem = "format" | "host_bits" | "count" | "no_links" | "family" | "links_count" | "twice";

export type RelayCheck = { ok: true; list: TrustedRelay[] } | { ok: false; problem: RelayProblem; line?: number; text?: string };

type Prefix = { ok: true; cidr: Cidr } | { ok: false; problem: "format" | "host_bits" };

/** The prefix of one address or prefix, or why it is not one. */
function prefixOf(text: string): Prefix {
  const strict = parseCidr(text);
  if (strict !== null) return { ok: true, cidr: strict };
  return { ok: false, problem: parseCidr(text, { strict: false }) !== null ? "host_bits" : "format" };
}

/** The host prefix of an address: `192.0.2.1` is `192.0.2.1/32`. */
export function hostPrefix(address: string): string {
  return address.includes("/") ? address : `${address}${address.includes(":") ? "/128" : "/32"}`;
}

/** The list of the lines of the text: blank lines are skipped, identical lines are kept once. */
export function relayList(text: string): RelayCheck {
  const list: TrustedRelay[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (line === "") continue;
    const refuse = (problem: RelayProblem): RelayCheck => ({ ok: false, problem, line: i + 1, text: line });
    const eq = line.indexOf("=");
    const relay = prefixOf(eq < 0 ? line : line.slice(0, eq).trim());
    if (!relay.ok) return refuse(relay.problem);
    const right = eq < 0 ? "" : line.slice(eq + 1).trim();
    if (right === "") return refuse("no_links");
    const links: Cidr[] = [];
    for (const item of right.split(",")) {
      const link = prefixOf(item.trim());
      if (!link.ok) return refuse(link.problem);
      if (link.cidr.version !== relay.cidr.version) return refuse("family");
      if (!links.some((l) => compareCidr(l, link.cidr) === 0)) links.push(link.cidr);
    }
    if (links.length > MAX_RELAY_LINKS) return refuse("links_count");
    links.sort(compareCidr);
    const entry = { relay: formatCidr(relay.cidr), links: links.map(formatCidr) };
    const same = list.find((e) => e.relay === entry.relay);
    if (same === undefined) list.push(entry);
    else if (same.links.join() !== entry.links.join()) return refuse("twice");
  }
  if (list.length > MAX_TRUSTED_RELAYS) return { ok: false, problem: "count" };
  return { ok: true, list };
}

/** The text of the form for a list: the inverse of `relayList`. */
export function relayText(list: readonly TrustedRelay[]): string {
  return list.map((e) => `${e.relay} = ${e.links.join(", ")}`).join("\n");
}

/** The entry that decides for the address a sender uses, as the server picks it: the most specific relay prefix that holds it. */
export function entryFor(list: readonly TrustedRelay[], source: string): TrustedRelay | undefined {
  const host = parseCidr(hostPrefix(source));
  let best: { entry: TrustedRelay; length: number } | undefined;
  for (const entry of list) {
    const relay = parseCidr(entry.relay);
    if (host === null || relay === null || !containsCidr(relay, host)) continue;
    if (best === undefined || relay.length > best.length) best = { entry, length: relay.length };
  }
  return best?.entry;
}

/** Whether the entry has a link that overlaps the network, which is what lets a scope count as one of its links. */
export function holdsLink(entry: TrustedRelay, network: string): boolean {
  const net = parseCidr(network);
  return net !== null && entry.links.some((l) => {
    const link = parseCidr(l);
    return link !== null && overlaps(link, net);
  });
}

/** The list with `link` added to the entry of the sender, or a new entry for the sender with that link. */
export function withLink(list: readonly TrustedRelay[], source: string, link: string): TrustedRelay[] {
  const entry = entryFor(list, source);
  if (entry === undefined) return [...list, { relay: hostPrefix(source), links: [link] }];
  return list.map((e) => (e === entry && !e.links.includes(link) ? { ...e, links: [...e.links, link] } : e));
}
