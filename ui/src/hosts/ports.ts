/**
 * What the Connect panel of the host page reads from the `services` facts of the probe
 * (docs/scanning.md, section 3): the open TCP ports of each address of the host, the default
 * ports of the RDP and SSH fields, and the links to the web interface. Pure functions.
 *
 * Nothing here guesses: a button or a link exists because a port was seen open, and a
 * disabled button says that it was not.
 */
import type { ObservedFact } from "../discovery/api";
import { isCurrent } from "../discovery/model";
import type { ConnectTarget } from "./Connect";

export const RDP_PORT = 3389;
export const SSH_PORT = 22;
/** Ports a field is filled with when the usual one is closed and one of these was seen open. */
export const RDP_ALTERNATIVES: readonly number[] = [RDP_PORT, 3390];
export const SSH_ALTERNATIVES: readonly number[] = [SSH_PORT, 2222];

/** The usual web ports; the scheme follows the port unless the fact marks the port as TLS. */
const HTTPS_PORT = 443;
const HTTP_PORT = 80;
/** The other web ports the panel recognises (Proxmox 8006, Home Assistant 8123), with their usual scheme. */
export const MORE_WEB_PORTS: readonly { port: number; scheme: Scheme }[] = [
  { port: 8080, scheme: "http" },
  { port: 8443, scheme: "https" },
  { port: 8006, scheme: "https" },
  { port: 8123, scheme: "http" },
  { port: 9443, scheme: "https" },
];

export type Scheme = "http" | "https";

/** The ports seen open at one address and when the last scan reported them. */
export interface Services {
  /** Open TCP ports, ascending, without duplicates. */
  open: number[];
  /** The open ports that answered a TLS handshake. */
  tls: number[];
  /** The newest `last_seen` of the facts, an ISO time. */
  at: string;
}

function sorted(ports: Iterable<number>): number[] {
  return [...new Set(ports)].sort((a, b) => a - b);
}

/**
 * The open ports of an address from the facts that name it: the union over every current
 * `services` fact (the `tcp_connect`, `tcp_syn` and `mdns` methods each report their own), and
 * the newest sighting. Null when no current `services` fact exists, which is not the same as a
 * fact with no open port.
 */
export function servicesOf(facts: readonly ObservedFact[], now = Date.now()): Services | null {
  const mine = facts.filter((f) => f.observed.type === "services" && isCurrent(f, now));
  if (mine.length === 0) return null;
  const open: number[] = [];
  const tls: number[] = [];
  for (const f of mine) {
    if (f.observed.type !== "services") continue;
    const data = f.observed.data as { open_tcp?: number[]; tls_tcp?: number[] };
    open.push(...(data.open_tcp ?? []));
    tls.push(...(data.tls_tcp ?? []));
  }
  const at = mine.map((f) => f.last_seen).sort((a, b) => Date.parse(b) - Date.parse(a))[0] as string;
  return { open: sorted(open), tls: sorted(tls).filter((p) => open.includes(p)), at };
}

/**
 * The port a field starts with: the first of `candidates` that is open on any scanned address,
 * else the usual port (`candidates[0]`). Nothing outside the candidates is ever chosen.
 */
export function defaultPort(scanned: readonly (Services | null)[], candidates: readonly number[]): number {
  const open = new Set(scanned.flatMap((s) => s?.open ?? []));
  return candidates.find((p) => open.has(p)) ?? (candidates[0] as number);
}

/** One link to a web interface. */
export interface WebLink {
  port: number;
  scheme: Scheme;
  /** The link, with the DNS name where the address has one. */
  url: string;
  /** The same link with the IP address, when `url` uses a name. */
  addressUrl: string | null;
}

export interface WebLinks {
  /** HTTPS on 443 when it is open, else HTTP on 80. */
  primary: WebLink | null;
  /** The plain HTTP link beside an HTTPS primary. */
  http: WebLink | null;
  /** The other web ports found open, ascending by the order of `MORE_WEB_PORTS`. */
  more: WebLink[];
}

/** A target with what was seen open at its address; the address is the IP address, absent for a name-only target. */
export interface Scanned {
  target: ConnectTarget;
  services: Services | null;
}

function urlHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function link(scheme: Scheme, port: number, entry: Scanned): WebLink {
  const defaultPortOf = scheme === "https" ? HTTPS_PORT : HTTP_PORT;
  const build = (host: string) => `${scheme}://${urlHost(host)}${port === defaultPortOf ? "" : `:${port}`}/`;
  const name = entry.target.address ?? entry.target.label;
  const ip = entry.target.ip;
  return { port, scheme, url: build(name), addressUrl: ip && ip !== name ? build(ip) : null };
}

/**
 * The entry to open a port at: the address that answered TLS on it, else the first (IPv4
 * first, as the targets are ordered) that has it open.
 */
function holder(entries: readonly Scanned[], port: number): Scanned | undefined {
  const open = entries.filter((e) => e.services?.open.includes(port));
  return open.find((e) => e.services?.tls.includes(port)) ?? open[0];
}

/** The web links of a host from what was seen open at its addresses. */
export function webLinks(entries: readonly Scanned[]): WebLinks {
  const https = holder(entries, HTTPS_PORT);
  const http = holder(entries, HTTP_PORT);
  const primary = https ? link("https", HTTPS_PORT, https) : http ? link("http", HTTP_PORT, http) : null;
  const secondary = https && http ? link("http", HTTP_PORT, http) : null;
  const more: WebLink[] = [];
  for (const { port, scheme } of MORE_WEB_PORTS) {
    const at = holder(entries, port);
    if (at) more.push(link(at.services?.tls.includes(port) ? "https" : scheme, port, at));
  }
  return { primary, http: secondary, more };
}
