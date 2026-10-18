// The pure helpers of the forwarding rules (docs/dns-resolver.md section 2.1), shared by the
// forwarders page and the first-run wizard's DNS step: the typed form of an upstream (the
// command line's `192.0.2.1`, `192.0.2.1:5353`, `[2001:db8::53]:853`, `192.0.2.80:443/dns-query`),
// the checks the server makes before it answers `dns.forwarder.invalid`, the root rule, and the
// well-known public resolvers that offer DNS over TLS (P2-Q5: examples the person may pick,
// never a default). No translated text here; the views map the problems to words.
import type { components } from "../../api/generated/schema";
import { normalizeIp, parseIp } from "../../ipam/ip";
import { canonical, validName } from "../model";

type S = components["schemas"];
export type Upstream = S["Upstream"];
export type ForwardTransport = S["ForwardTransport"];

export const TRANSPORTS: readonly ForwardTransport[] = ["plain", "dot", "doh"];

/** The most upstreams one rule takes. */
export const MAX_UPSTREAMS = 16;

/** The port a transport uses when an upstream names none. */
export function defaultPort(transport: ForwardTransport): number {
  return transport === "dot" ? 853 : transport === "doh" ? 443 : 53;
}

/** Whether a transport needs the name in the upstreams' certificates. */
export function needsTlsName(transport: ForwardTransport): boolean {
  return transport !== "plain";
}

export type UpstreamProblem = "address" | "port" | "path" | "path_transport";

export type ParsedUpstream = { ok: true; upstream: Upstream } | { ok: false; problem: UpstreamProblem };

/** One upstream in its typed form; an IPv6 address with a port is written in brackets. */
export function parseUpstream(raw: string, transport: ForwardTransport): ParsedUpstream {
  let text = raw.trim();
  let path: string | undefined;
  const slash = text.indexOf("/");
  if (slash >= 0) {
    path = text.slice(slash);
    text = text.slice(0, slash);
  }
  let address = text;
  let portText: string | undefined;
  const bracket = /^\[([^\]]+)\](?::(.*))?$/.exec(text);
  if (bracket) {
    address = bracket[1] ?? "";
    portText = bracket[2];
  } else if ((text.match(/:/g) ?? []).length === 1) {
    const colon = text.indexOf(":");
    address = text.slice(0, colon);
    portText = text.slice(colon + 1);
  }
  const ip = parseIp(address);
  if (!ip) return { ok: false, problem: "address" };
  const upstream: Upstream = { address: address.toLowerCase() };
  if (portText !== undefined) {
    if (!/^\d{1,5}$/.test(portText)) return { ok: false, problem: "port" };
    const port = Number(portText);
    if (port < 1 || port > 65_535) return { ok: false, problem: "port" };
    upstream.port = port;
  }
  if (path !== undefined) {
    if (transport !== "doh") return { ok: false, problem: "path_transport" };
    if (!/^\/[\x21-\x7e]*$/.test(path)) return { ok: false, problem: "path" };
    upstream.path = path;
  }
  return { ok: true, upstream };
}

/** The typed form of an upstream (what `parseUpstream` reads back). */
export function upstreamText(u: Upstream): string {
  const v6 = u.address.includes(":");
  const host = v6 && u.port ? `[${u.address}]` : u.address;
  return `${host}${u.port ? `:${u.port}` : ""}${u.path ?? ""}`;
}

/** The address and port an upstream is asked on, with the transport's default port. */
export function upstreamEndpoint(u: Upstream, transport: ForwardTransport): string {
  const port = u.port ?? defaultPort(transport);
  return u.address.includes(":") ? `[${u.address}]:${port}` : `${u.address}:${port}`;
}

/** Splits the upstream list typed one per line (commas and spaces separate too). */
export function splitUpstreams(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** A rule as a form edits it: the suffix, the upstreams as typed, the transport and the TLS name. */
export interface RuleDraft {
  suffix: string;
  upstreams: string;
  transport: ForwardTransport;
  tlsName: string;
}

export type RuleProblem =
  | { field: "suffix"; problem: "name" }
  | { field: "upstreams"; problem: "none" | "too_many" | "duplicate" }
  | { field: "upstreams"; problem: UpstreamProblem; entry: string }
  | { field: "tls_name"; problem: "required" | "name" };

export type CheckedRule =
  | { ok: true; suffix: string; upstreams: Upstream[]; transport: ForwardTransport; tlsName: string | null }
  | { ok: false; problems: RuleProblem[] };

/** A DNS name or an IP address, the forms a certificate name of an upstream takes. */
export function validTlsName(name: string): boolean {
  const n = canonical(name);
  if (parseIp(n)) return true;
  return n !== "." && n !== "" && !n.includes("*") && validName(n);
}

/** The local checks of a rule; the server checks again (`dns.forwarder.invalid`). */
export function checkRule(draft: RuleDraft, options: { suffix?: boolean } = {}): CheckedRule {
  const problems: RuleProblem[] = [];
  const suffix = canonical(draft.suffix) || ".";
  if (options.suffix !== false && (!validName(suffix) || suffix.includes("*"))) problems.push({ field: "suffix", problem: "name" });
  const entries = splitUpstreams(draft.upstreams);
  const upstreams: Upstream[] = [];
  if (entries.length === 0) problems.push({ field: "upstreams", problem: "none" });
  else if (entries.length > MAX_UPSTREAMS) problems.push({ field: "upstreams", problem: "too_many" });
  else {
    const seen = new Set<string>();
    for (const entry of entries) {
      const parsed = parseUpstream(entry, draft.transport);
      if (!parsed.ok) {
        problems.push({ field: "upstreams", problem: parsed.problem, entry });
        break;
      }
      const key = upstreamEndpoint(parsed.upstream, draft.transport) + (parsed.upstream.path ?? "");
      if (seen.has(key)) {
        problems.push({ field: "upstreams", problem: "duplicate" });
        break;
      }
      seen.add(key);
      upstreams.push(parsed.upstream);
    }
  }
  const tlsName = canonical(draft.tlsName);
  if (needsTlsName(draft.transport)) {
    if (tlsName === "") problems.push({ field: "tls_name", problem: "required" });
    else if (!validTlsName(tlsName)) problems.push({ field: "tls_name", problem: "name" });
  } else if (tlsName !== "" && !validTlsName(tlsName)) {
    problems.push({ field: "tls_name", problem: "name" });
  }
  if (problems.length > 0) return { ok: false, problems };
  return { ok: true, suffix, upstreams, transport: draft.transport, tlsName: tlsName === "" ? null : tlsName };
}

/** Whether a rule is the root rule, the default forwarder of the store. */
export function isRoot(rule: { suffix: string }): boolean {
  return rule.suffix === ".";
}

/** Rules in the order the page lists them: the root first, then by suffix from the root down. */
export function ruleOrder(a: { suffix: string }, b: { suffix: string }): number {
  if (isRoot(a) !== isRoot(b)) return isRoot(a) ? -1 : 1;
  const la = a.suffix.split(".").reverse();
  const lb = b.suffix.split(".").reverse();
  for (let i = 0; i < Math.min(la.length, lb.length); i += 1) {
    const x = la[i] as string;
    const y = lb[i] as string;
    if (x !== y) return x < y ? -1 : 1;
  }
  return la.length - lb.length;
}

// ---------------------------------------------------------------------------------
// Well-known public resolvers (docs/dns-resolver.md section 4.2)

export interface KnownResolver {
  /** The operator's name, shown as it is (a proper name, not translated). */
  name: string;
  /** The name in its certificates, the `tls_name` of a DoT or DoH rule. */
  tlsName: string;
  addresses: readonly string[];
}

/** The examples the docs name; never used unless the person types one of their addresses. */
export const KNOWN_RESOLVERS: readonly KnownResolver[] = [
  { name: "Quad9", tlsName: "dns.quad9.net", addresses: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"] },
  { name: "Cloudflare", tlsName: "cloudflare-dns.com", addresses: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"] },
  { name: "Google Public DNS", tlsName: "dns.google", addresses: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"] },
];

/**
 * The resolver whose addresses these all are, when every typed upstream belongs to one of the
 * known resolvers: then DoT with its certificate name can be offered. Otherwise none.
 */
export function knownResolver(upstreams: readonly string[]): KnownResolver | undefined {
  const addresses = upstreams
    .map((entry) => parseUpstream(entry, "doh"))
    .map((parsed) => (parsed.ok ? normalizeIp(parsed.upstream.address) : null));
  if (addresses.length === 0 || addresses.some((a) => a === null)) return undefined;
  return KNOWN_RESOLVERS.find((r) => addresses.every((a) => r.addresses.some((k) => normalizeIp(k) === a)));
}
