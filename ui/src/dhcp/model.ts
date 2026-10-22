// Pure helpers of the DHCP area: lease times in human units, option values to and from the
// typed `OptionData` of the API, MAC patterns, hexadecimal values, the drafts of matches and
// policy terms, the local checks of exclusions and the order of policies. No DOM, no i18n:
// problems are short codes that the views translate (`dhcp.check.<code>`); the words for a
// match, a condition and an action are in words.ts.
import { canonical, validName } from "../dns/model";
import { compareIp, containsIp, formatCidr, formatIp, parseCidr, parseIp, type Cidr } from "../ipam/ip";
import type {
  LeaseTimes,
  Match,
  OptionData,
  OptionKind,
  Policy,
  PolicyAction,
  Term,
} from "./types";
import { MAX_LEASE_SECS } from "./types";

// ---------------------------------------------------------------------------------
// Lease times

export type LeaseUnit = "minutes" | "hours" | "days";
export const LEASE_UNITS: readonly LeaseUnit[] = ["minutes", "hours", "days"];
const UNIT_SECS: Readonly<Record<LeaseUnit, number>> = { minutes: 60, hours: 3600, days: 86_400 };

/** A time as typed: a number and its unit. */
export interface Span {
  value: string;
  unit: LeaseUnit;
}

/** Seconds in the largest unit that divides them; a time that is not a whole minute shows as minutes with decimals. */
export function spanOf(secs: number): Span {
  if (secs > 0 && secs % 86_400 === 0) return { value: String(secs / 86_400), unit: "days" };
  if (secs > 0 && secs % 3600 === 0) return { value: String(secs / 3600), unit: "hours" };
  if (secs % 60 === 0) return { value: String(secs / 60), unit: "minutes" };
  return { value: String(Math.round((secs / 60) * 1000) / 1000), unit: "minutes" };
}

/** The seconds of a span; null when the number is not positive. */
export function secsOf(span: Span): number | null {
  const text = span.value.trim().replace(",", ".");
  if (!/^\d+(\.\d+)?$/.test(text)) return null;
  const secs = Math.round(Number(text) * UNIT_SECS[span.unit]);
  return Number.isSafeInteger(secs) && secs > 0 ? secs : null;
}

/** The three times the forms edit; T1 and T2 are kept as the server has them. */
export interface LeaseDraft {
  default: Span;
  min: Span;
  max: Span;
}

export type LeaseField = keyof LeaseDraft;
export type LeaseProblem = "number" | "order" | "year";

export function draftOfLease(lease: LeaseTimes): LeaseDraft {
  return { default: spanOf(lease.default_secs), min: spanOf(lease.min_secs), max: spanOf(lease.max_secs) };
}

/** `0 < min <= default <= max <= one year`, checked before anything is sent. T1 and T2 of `keep` stay while they still fit. */
export function leaseOfDraft(
  draft: LeaseDraft,
  keep?: LeaseTimes | null,
): { ok: true; lease: LeaseTimes } | { ok: false; field: LeaseField; problem: LeaseProblem } {
  const def = secsOf(draft.default);
  const min = secsOf(draft.min);
  const max = secsOf(draft.max);
  if (min === null) return { ok: false, field: "min", problem: "number" };
  if (def === null) return { ok: false, field: "default", problem: "number" };
  if (max === null) return { ok: false, field: "max", problem: "number" };
  if (min > def) return { ok: false, field: "min", problem: "order" };
  if (def > max) return { ok: false, field: "default", problem: "order" };
  if (max > MAX_LEASE_SECS) return { ok: false, field: "max", problem: "year" };
  const lease: LeaseTimes = { default_secs: def, min_secs: min, max_secs: max };
  const t1 = keep?.t1_secs ?? undefined;
  const t2 = keep?.t2_secs ?? undefined;
  if (t1 !== undefined && t2 !== undefined && t1 < t2 && t2 < def) {
    lease.t1_secs = t1;
    lease.t2_secs = t2;
  }
  return { ok: true, lease };
}

export function sameLease(a: LeaseTimes | null | undefined, b: LeaseTimes | null | undefined): boolean {
  if (!a || !b) return !a && !b;
  return a.default_secs === b.default_secs && a.min_secs === b.min_secs && a.max_secs === b.max_secs && (a.t1_secs ?? null) === (b.t1_secs ?? null) && (a.t2_secs ?? null) === (b.t2_secs ?? null);
}

// ---------------------------------------------------------------------------------
// Names, hexadecimal values and MAC patterns

/** A class, policy or shared network name: 1 to 64 characters of a-z, 0-9 and `-`. */
export function validDhcpName(name: string): boolean {
  return /^[a-z0-9-]{1,64}$/.test(name);
}

/** Octets as the user typed them (`c0ff`, `c0:ff`, `0xc0ff`) to lowercase hexadecimal; null unless 1 to `max` whole octets. */
export function parseHex(text: string, max = 255): string | null {
  const s = text.trim().replace(/^0x/i, "").replace(/[\s:.-]/g, "");
  if (s === "" || s.length % 2 !== 0 || s.length > max * 2 || !/^[0-9a-f]+$/i.test(s)) return null;
  return s.toLowerCase();
}

/** A MAC pattern in its stored form (lowercase, colons, six positions), or null: six hexadecimal octets, `*` for any octet, or a prefix ending in `*`. */
export function checkMacPattern(text: string): string | null {
  const parts = text.trim().split(/[:-]/);
  if (parts.length === 0 || parts.length > 6) return null;
  if (parts.length < 6 && parts[parts.length - 1] !== "*") return null;
  const out: string[] = [];
  for (const part of parts) {
    if (part === "*") out.push("*");
    else if (/^[0-9a-f]{2}$/i.test(part)) out.push(part.toLowerCase());
    else return null;
  }
  while (out.length < 6) out.push("*");
  return out.join(":");
}

/** A plain MAC address (no wildcard) in its stored form, or null. */
export function checkMac(text: string): string | null {
  const pattern = checkMacPattern(text);
  return pattern !== null && !pattern.includes("*") ? pattern : null;
}

// ---------------------------------------------------------------------------------
// Option values

/** The type of an option as the catalog or its definition gives it. */
export interface OptionShape {
  kind: OptionKind;
  array: boolean;
}

export type ValueProblem = "empty" | "ipv4" | "ipv6" | "prefix" | "number" | "range" | "bool" | "name" | "route" | "hex" | "count";

const LIST_SEPARATORS = /[\s,;]+/;

/** The entries of a list typed with commas, spaces or lines. */
export function splitValues(text: string): string[] {
  return text.split(LIST_SEPARATORS).filter((s) => s !== "");
}

const UNSIGNED_MAX: Readonly<Partial<Record<OptionKind, number>>> = { u8: 255, u16: 65_535, u32: 4_294_967_295 };

type Parsed<T> = { ok: true; value: T } | { ok: false; problem: ValueProblem };

function each<T>(items: readonly string[], parse: (item: string) => Parsed<T>): Parsed<T[]> {
  const out: T[] = [];
  for (const item of items) {
    const parsed = parse(item);
    if (!parsed.ok) return parsed;
    out.push(parsed.value);
  }
  return { ok: true, value: out };
}

/** The typed data a text stands for under `shape`, or what is wrong with it. Addresses, numbers and names are checked as the server checks them. */
export function parseOptionText(shape: OptionShape, text: string): { ok: true; data: OptionData } | { ok: false; problem: ValueProblem } {
  const { kind, array } = shape;
  const done = (data: OptionData) => ({ ok: true as const, data });
  const fail = (problem: ValueProblem) => ({ ok: false as const, problem });
  if (kind === "empty") return done("empty");
  if (kind === "string") {
    const value = text.replace(/[\r\n]+/g, " ").trim();
    return value === "" ? fail("empty") : done({ text: value });
  }
  if (kind === "binary") {
    const hex = parseHex(text, 4096);
    return hex === null ? fail("hex") : done({ binary: hex });
  }
  if (kind === "classless_routes") {
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "");
    if (lines.length === 0) return fail("empty");
    const routes = each(lines, (line) => {
      const m = /^(\S+)\s+via\s+(\S+)$/i.exec(line);
      const destination = m && (m[1] ?? "").includes("/") ? parseCidr(m[1] ?? "", { strict: true }) : null;
      const router = m ? parseIp(m[2] ?? "") : null;
      if (!destination || destination.version !== 4 || !router || router.version !== 4) return { ok: false, problem: "route" } as const;
      return { ok: true, value: { destination: formatCidr(destination), router: formatIp(router) } } as const;
    });
    return routes.ok ? done({ routes: routes.value }) : fail(routes.problem);
  }
  if (kind === "i32") {
    const s = text.trim();
    if (!/^-?\d+$/.test(s)) return fail("number");
    const n = Number(s);
    return n >= -2_147_483_648 && n <= 2_147_483_647 ? done({ signed: n }) : fail("range");
  }
  const items = splitValues(text);
  if (items.length === 0) return fail("empty");
  if (!array && items.length > 1) return fail("count");
  switch (kind) {
    case "ipv4_address":
    case "ipv6_address": {
      const version = kind === "ipv4_address" ? 4 : 6;
      const values = each(items, (item) => {
        const ip = parseIp(item);
        return ip && ip.version === version ? ({ ok: true, value: formatIp(ip) } as const) : ({ ok: false, problem: version === 4 ? "ipv4" : "ipv6" } as const);
      });
      if (!values.ok) return fail(values.problem);
      return done(version === 4 ? { ipv4: { values: values.value } } : { ipv6: { values: values.value } });
    }
    case "ipv6_prefix": {
      const values = each(items, (item) => {
        const cidr = item.includes("/") ? parseCidr(item, { strict: true }) : null;
        return cidr && cidr.version === 6 ? ({ ok: true, value: formatCidr(cidr) } as const) : ({ ok: false, problem: "prefix" } as const);
      });
      return values.ok ? done({ ipv6_prefix: { values: values.value } }) : fail(values.problem);
    }
    case "u8":
    case "u16":
    case "u32": {
      const limit = UNSIGNED_MAX[kind] ?? 0;
      const values = each(items, (item) => {
        if (!/^\d+$/.test(item)) return { ok: false, problem: "number" } as const;
        const n = Number(item);
        return n <= limit ? ({ ok: true, value: n } as const) : ({ ok: false, problem: "range" } as const);
      });
      return values.ok ? done({ unsigned: values.value }) : fail(values.problem);
    }
    case "bool": {
      const values = each(items, (item) => {
        const s = item.toLowerCase();
        return s === "true" || s === "false" ? ({ ok: true, value: s === "true" } as const) : ({ ok: false, problem: "bool" } as const);
      });
      return values.ok ? done({ bool: values.value }) : fail(values.problem);
    }
    case "fqdn": {
      const values = each(items, (item) => {
        const name = canonical(item);
        return validName(name) && name !== "." && !name.includes("*") ? ({ ok: true, value: name } as const) : ({ ok: false, problem: "name" } as const);
      });
      return values.ok ? done({ names: values.value }) : fail(values.problem);
    }
    default:
      return fail("empty");
  }
}

/** The text of typed option data for display: lists with commas, routes one per line. */
export function dataText(data: OptionData): string {
  if (data === "empty") return "";
  if ("ipv4" in data) return data.ipv4.values.join(", ");
  if ("ipv6" in data) return data.ipv6.values.join(", ");
  if ("ipv6_prefix" in data) return data.ipv6_prefix.values.join(", ");
  if ("unsigned" in data) return data.unsigned.join(", ");
  if ("signed" in data) return String(data.signed);
  if ("bool" in data) return data.bool.map(String).join(", ");
  if ("text" in data) return data.text;
  if ("names" in data) return data.names.join(", ");
  if ("routes" in data) return data.routes.map((r) => `${r.destination} via ${r.router}`).join("\n");
  return data.binary;
}

/** The kind of option data a typed value holds, for a value whose definition is not at hand. */
export function kindOfData(data: OptionData): OptionKind {
  if (data === "empty") return "empty";
  if ("ipv4" in data) return "ipv4_address";
  if ("ipv6" in data) return "ipv6_address";
  if ("ipv6_prefix" in data) return "ipv6_prefix";
  if ("unsigned" in data) return "u32";
  if ("signed" in data) return "i32";
  if ("bool" in data) return "bool";
  if ("text" in data) return "string";
  if ("names" in data) return "fqdn";
  if ("routes" in data) return "classless_routes";
  return "binary";
}

// ---------------------------------------------------------------------------------
// Matches and terms

export type MatchKind = "vendor_class" | "user_class" | "mac" | "client_id" | "circuit_id" | "remote_id" | "architecture" | "host_name";
export const MATCH_KINDS: readonly MatchKind[] = ["vendor_class", "user_class", "mac", "client_id", "circuit_id", "remote_id", "architecture", "host_name"];

/** Kinds whose value can be an exact text or a prefix. */
export function hasPrefix(kind: MatchKind): boolean {
  return kind === "vendor_class" || kind === "host_name";
}

/** A match as the editor holds it: its kind, the value as typed and the prefix flag. */
export interface MatchDraft {
  kind: MatchKind;
  value: string;
  prefix: boolean;
}

export function emptyMatch(kind: MatchKind = "vendor_class"): MatchDraft {
  return { kind, value: "", prefix: false };
}

export function matchKind(match: Match): MatchKind {
  if ("vendor_class" in match) return "vendor_class";
  if ("user_class" in match) return "user_class";
  if ("mac" in match) return "mac";
  if ("client_id" in match) return "client_id";
  if ("circuit_id" in match) return "circuit_id";
  if ("remote_id" in match) return "remote_id";
  if ("architecture" in match) return "architecture";
  return "host_name";
}

export function draftOfMatch(match: Match): MatchDraft {
  if ("vendor_class" in match) return { kind: "vendor_class", value: match.vendor_class.value, prefix: match.vendor_class.prefix ?? false };
  if ("user_class" in match) return { kind: "user_class", value: match.user_class.value, prefix: false };
  if ("mac" in match) return { kind: "mac", value: match.mac.pattern, prefix: false };
  if ("client_id" in match) return { kind: "client_id", value: match.client_id.value, prefix: false };
  if ("circuit_id" in match) return { kind: "circuit_id", value: match.circuit_id.value, prefix: false };
  if ("remote_id" in match) return { kind: "remote_id", value: match.remote_id.value, prefix: false };
  if ("architecture" in match) return { kind: "architecture", value: String(match.architecture.code), prefix: false };
  return { kind: "host_name", value: match.host_name.value, prefix: match.host_name.prefix ?? false };
}

export type MatchProblem = "empty" | "long" | "mac" | "hex" | "number";

/** The match a draft stands for, or what is wrong with it. */
export function matchOfDraft(draft: MatchDraft): { ok: true; match: Match } | { ok: false; problem: MatchProblem } {
  const text = draft.value.trim();
  const done = (match: Match) => ({ ok: true as const, match });
  if (text === "") return { ok: false, problem: "empty" };
  switch (draft.kind) {
    case "vendor_class":
      return text.length > 255 ? { ok: false, problem: "long" } : done({ vendor_class: { value: text, prefix: draft.prefix } });
    case "host_name":
      return text.length > 255 ? { ok: false, problem: "long" } : done({ host_name: { value: text, prefix: draft.prefix } });
    case "user_class":
      return text.length > 255 ? { ok: false, problem: "long" } : done({ user_class: { value: text } });
    case "mac": {
      const pattern = checkMacPattern(text);
      return pattern === null ? { ok: false, problem: "mac" } : done({ mac: { pattern } });
    }
    case "client_id":
    case "circuit_id":
    case "remote_id": {
      const hex = parseHex(text);
      if (hex === null) return { ok: false, problem: "hex" };
      return done(draft.kind === "client_id" ? { client_id: { value: hex } } : draft.kind === "circuit_id" ? { circuit_id: { value: hex } } : { remote_id: { value: hex } });
    }
    case "architecture": {
      if (!/^\d+$/.test(text) || Number(text) > 65_535) return { ok: false, problem: "number" };
      return done({ architecture: { code: Number(text) } });
    }
  }
}

export type TermKind = "class" | "not_class" | "match" | "not_match";
export const TERM_KINDS: readonly TermKind[] = ["class", "not_class", "match", "not_match"];

/** One term as the policy editor holds it: a class (by identifier) or a match, each possibly negated. */
export interface TermDraft {
  kind: TermKind;
  class_id: string;
  match: MatchDraft;
}

export function emptyTerm(): TermDraft {
  return { kind: "class", class_id: "", match: emptyMatch() };
}

export function draftOfTerm(term: Term): TermDraft {
  if ("class" in term) return { kind: "class", class_id: term.class, match: emptyMatch() };
  if ("not_class" in term) return { kind: "not_class", class_id: term.not_class, match: emptyMatch() };
  if ("match" in term) return { kind: "match", class_id: "", match: draftOfMatch(term.match) };
  return { kind: "not_match", class_id: "", match: draftOfMatch(term.not_match) };
}

export type TermProblem = "class" | MatchProblem;

export function termOfDraft(draft: TermDraft): { ok: true; term: Term } | { ok: false; problem: TermProblem } {
  if (draft.kind === "class" || draft.kind === "not_class") {
    if (draft.class_id === "") return { ok: false, problem: "class" };
    return { ok: true, term: draft.kind === "class" ? { class: draft.class_id } : { not_class: draft.class_id } };
  }
  const match = matchOfDraft(draft.match);
  if (!match.ok) return match;
  return { ok: true, term: draft.kind === "match" ? { match: match.match } : { not_match: match.match } };
}

// ---------------------------------------------------------------------------------
// Policies

/**
 * The policies in the order they are evaluated: those of each scope (the scopes by network),
 * lowest order first, then the policies of the server, which apply after the scope's own.
 */
export function policyOrder(policies: readonly Policy[], networkOf: (scope: string) => string): Policy[] {
  const key = (p: Policy) => (p.scope ? networkOf(p.scope) : "￿");
  return [...policies].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka !== kb) return ka < kb ? -1 : 1;
    return a.order - b.order || a.name.localeCompare(b.name);
  });
}

/** Whether a policy action sets anything. */
export function actionIsEmpty(action: PolicyAction | undefined): boolean {
  return !action || (!action.range && !action.lease && !action.ddns);
}

// ---------------------------------------------------------------------------------
// Exclusions

export type ExclusionProblem = "first" | "last" | "order" | "outside";

/** The local check of an exclusion: two IPv4 addresses, the first not after the last, both inside the network. */
export function checkExclusion(first: string, last: string, network: Cidr | null): ExclusionProblem | null {
  const a = parseIp(first);
  const b = parseIp(last);
  if (!a || a.version !== 4) return "first";
  if (!b || b.version !== 4) return "last";
  if (compareIp(a, b) > 0) return "order";
  if (network && (!containsIp(network, a) || !containsIp(network, b))) return "outside";
  return null;
}

/** The network of a scope as a parsed prefix. */
export function networkOf(cidr: string): Cidr | null {
  return parseCidr(cidr);
}

/** Whether a prefix is an IPv4 network, the only family the server serves in Phase 3. */
export function isIpv4(cidr: string): boolean {
  return !cidr.includes(":");
}

// ---------------------------------------------------------------------------------
// Utilization

/** The used share of a scope as a whole percent. */
export function percentOf(share: number): number {
  return Math.max(0, Math.min(100, Math.round(share * 100)));
}
