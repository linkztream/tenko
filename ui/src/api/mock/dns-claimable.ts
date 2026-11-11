// The claimable names of a Windows zone file in the mock DNS service: which RRsets with an
// aging mark are candidates, which of them stay static and why, the rule of the operator, the
// digest that approves a listing, and the page of that listing. Pure functions; dns-model.ts
// (the zone file import) calls them and owns the refusals.
//
// The server decides the same things with more reasons (`tenko_node`, `too_many` in a
// partial import) and with IPv6 prefixes in the rule; the mock keeps IPv4 prefixes only (an
// AAAA RRset is outside a rule with a prefix) because the tests of the UI need the shape of the
// answer, not every rule. Documentation values only.
import type { components } from "../generated/schema";
import { canonical, validName } from "../../dns/model";

type S = components["schemas"];
type RecordData = S["RecordData"];
export type ClaimableName = S["ClaimableName"];
export type ClaimHeldName = S["ClaimHeldName"];

/** More candidates than this can not become claimable (the server's bound). */
export const CLAIM_OVERFLOW = 250_000;
/** The page of a listing when `limit` is absent, and its largest value. */
export const CLAIM_PAGE = 1_000;
export const CLAIM_PAGE_MAX = 5_000;
/** How many held-back names the answer lists. */
export const CLAIM_HELD_LISTED = 1_000;

/** An IPv4 prefix; `null` for an IPv6 one, which matches nothing in the mock. */
type Prefix = { base: number; length: number } | null;

export interface ClaimRule {
  under: string[];
  within: Prefix[];
  except: Set<string>;
}

/** The `claimable` part of an import body, checked. */
export interface ClaimPart {
  rule: ClaimRule;
  approve: string | undefined;
  after: string | undefined;
  limit: number;
}

const EMPTY_RULE = (): ClaimRule => ({ under: [], within: [], except: new Set() });

function ipv4(text: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return (((parts[0] as number) * 256 + (parts[1] as number)) * 256 + (parts[2] as number)) * 256 + (parts[3] as number);
}

function inside(address: number, prefix: Prefix): boolean {
  if (!prefix) return false;
  const size = 2 ** (32 - prefix.length);
  return Math.floor(address / size) === Math.floor(prefix.base / size);
}

function prefixOf(text: string): Prefix | undefined {
  const m = /^([0-9a-f.:]+)\/(\d{1,3})$/i.exec(text);
  if (!m) return undefined;
  const length = Number(m[2]);
  if ((m[1] as string).includes(":")) return length <= 128 ? null : undefined;
  const base = ipv4(m[1] as string);
  return base !== null && length <= 32 ? { base, length } : undefined;
}

function list(raw: unknown, field: string, max: number, refuse: (field: string) => never): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.length > max || raw.some((x) => typeof x !== "string")) return refuse(field);
  return raw as string[];
}

/**
 * Checks the `claimable` part of an import body. Absent gives the defaults; present outside the
 * Windows dialect, or malformed, is refused naming the field.
 */
export function claimPart(raw: unknown, windows: boolean, refuse: (field: string) => never): ClaimPart {
  const part: ClaimPart = { rule: EMPTY_RULE(), approve: undefined, after: undefined, limit: CLAIM_PAGE };
  if (raw === undefined || raw === null) return part;
  if (!windows) return refuse("claimable");
  if (typeof raw !== "object" || Array.isArray(raw)) return refuse("claimable");
  const body = raw as Record<string, unknown>;
  for (const name of list(body.under, "claimable.under", 256, refuse)) {
    const n = canonical(name);
    if (!validName(n)) return refuse("claimable.under");
    part.rule.under.push(n);
  }
  for (const text of list(body.within, "claimable.within", 256, refuse)) {
    const prefix = prefixOf(text);
    if (prefix === undefined) return refuse("claimable.within");
    part.rule.within.push(prefix);
  }
  for (const name of list(body.except, "claimable.except", 10_000, refuse)) {
    const n = canonical(name);
    if (!validName(n)) return refuse("claimable.except");
    part.rule.except.add(n);
  }
  if (body.approve !== undefined && body.approve !== null) {
    if (typeof body.approve !== "string" || !/^[0-9a-f]{64}$/.test(body.approve)) return refuse("claimable.approve");
    part.approve = body.approve;
  }
  if (body.after !== undefined && body.after !== null) {
    if (typeof body.after !== "string" || body.after === "") return refuse("claimable.after");
    part.after = body.after;
  }
  if (body.limit !== undefined && body.limit !== null) {
    if (typeof body.limit !== "number" || !Number.isInteger(body.limit) || body.limit < 1 || body.limit > CLAIM_PAGE_MAX) return refuse("claimable.limit");
    part.limit = body.limit;
  }
  return part;
}

/** One RRset of the file, as the plan reads it; the caller passes them in name order. */
export interface ClaimSet {
  name: string;
  type: string;
  line: number;
  records: RecordData[];
  /** Every record of the RRset carries an aging mark. */
  aged: boolean;
  /** Some records carry the mark and some do not. */
  mixed: boolean;
}

export interface ClaimContext {
  /** The zone name. */
  zone: string;
  /** The hosts the zone's NS records name (the file's and the zone's). */
  nameServers: ReadonlySet<string>;
  /** The targets of MX, SRV, CNAME and DNAME records in the file. */
  serviceTargets: ReadonlySet<string>;
  /** The names that hold a type other than A, AAAA and PTR (in the file or the zone). */
  otherData: ReadonlySet<string>;
}

export interface ClaimPlan {
  /** The candidates an approval makes claimable, in name order. */
  claimable: ClaimableName[];
  /** The candidates that stay static, in name order (never `not_approved`). */
  held: ClaimHeldName[];
  overflow: boolean;
}

const HOST_TYPES = new Set(["A", "AAAA", "PTR"]);

function targets(set: ClaimSet): string[] {
  return set.records.map((r) => (r.type === "PTR" ? r.target : r.type === "A" || r.type === "AAAA" ? r.address : ""));
}

/** The host names an RRset stands for: its owner (A, AAAA) or the targets (PTR). */
function hostsOf(set: ClaimSet): string[] {
  return set.type === "PTR" ? targets(set) : [set.name];
}

function addressOf(name: string): number | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$/.exec(name);
  return m ? ipv4(`${m[4]}.${m[3]}.${m[2]}.${m[1]}`) : null;
}

function underAny(name: string, under: readonly string[]): boolean {
  return under.some((u) => name === u || name.endsWith(`.${u}`));
}

function outsideRule(set: ClaimSet, rule: ClaimRule): boolean {
  const hosts = hostsOf(set);
  if (rule.under.length > 0 && !hosts.every((h) => underAny(h, rule.under))) return true;
  if (rule.except.has(set.name) || hosts.some((h) => rule.except.has(h))) return true;
  if (rule.within.length > 0) {
    const addresses = set.type === "PTR" ? [addressOf(set.name)] : set.records.map((r) => (r.type === "A" ? ipv4(r.address) : null));
    if (!addresses.every((a) => a !== null && rule.within.some((p) => inside(a, p)))) return true;
  }
  return false;
}

/** Why an aged RRset stays static, or `null` when it is claimable. */
function heldReason(set: ClaimSet, ctx: ClaimContext, rule: ClaimRule): S["ClaimHeldReason"] | null {
  const hosts = hostsOf(set);
  const relative = (h: string) => (h === ctx.zone ? [] : h.endsWith(`.${ctx.zone}`) ? h.slice(0, -ctx.zone.length - 1).split(".") : h.split("."));
  if (hosts.some((h) => h === ctx.zone || relative(h).some((l) => l.startsWith("_") || l === "*"))) return "reserved";
  if (hosts.some((h) => /^(wpad|isatap)$/.test(h.split(".")[0] ?? ""))) return "service_name";
  if (hosts.some((h) => ctx.nameServers.has(h))) return "name_server";
  if (hosts.some((h) => ctx.serviceTargets.has(h))) return "service_target";
  if (set.type === "PTR" ? new Set(hosts).size !== 1 : relative(set.name).length !== 1) return "not_a_host";
  if (set.mixed || hosts.some((h) => ctx.otherData.has(h)) || ctx.otherData.has(set.name)) return "other_data";
  if (outsideRule(set, rule)) return "rule";
  return null;
}

/** Sorts the aged RRsets of a Windows file into the claimable ones and the held-back ones. */
export function planClaims(sets: readonly ClaimSet[], ctx: ClaimContext, rule: ClaimRule): ClaimPlan {
  const claimable: ClaimableName[] = [];
  const held: ClaimHeldName[] = [];
  for (const set of sets) {
    if (!HOST_TYPES.has(set.type) || (!set.aged && !set.mixed)) continue;
    const reason = heldReason(set, ctx, rule);
    if (reason) {
      held.push({ name: set.name, rtype: set.type as ClaimHeldName["rtype"], line: set.line, reason });
      continue;
    }
    const shown = targets(set);
    const host = (set.type === "PTR" ? shown[0] : set.name) ?? set.name;
    claimable.push({
      name: set.name,
      rtype: set.type as ClaimableName["rtype"],
      line: set.line,
      claimant: `${(host.split(".")[0] as string).toUpperCase()}$`,
      records: shown.slice(0, 4),
      more: Math.max(0, shown.length - 4),
    });
  }
  if (claimable.length > CLAIM_OVERFLOW) {
    const tooMany = claimable.map((c): ClaimHeldName => ({ name: c.name, rtype: c.rtype, line: c.line, reason: "too_many" }));
    return { claimable: [], held: [...held, ...tooMany], overflow: true };
  }
  return { claimable, held, overflow: false };
}

/** The key of an entry in the listing, and the cursor that follows it. */
export const claimKey = (c: { name: string; rtype: string }): string => `${c.name}/${c.rtype}`;

/**
 * The digest that approves a listing: 64 hex characters over the zone, the file text and the
 * sorted `name/type` list. NOT A CRYPTOGRAPHIC HASH: eight FNV-1a passes with different seeds,
 * enough for the mock to tell a changed file or rule from an unchanged one (the server uses
 * SHA-256).
 */
export function claimDigest(zoneId: string, fileText: string, claimable: readonly ClaimableName[]): string {
  const input = `${zoneId}\n${fileText}\n${claimable.map(claimKey).join("\n")}`;
  let out = "";
  for (let seed = 1; seed <= 8; seed += 1) {
    let h = (0x811c9dc5 ^ Math.imul(seed, 0x9e3779b1)) >>> 0;
    for (let i = 0; i < input.length; i += 1) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out += h.toString(16).padStart(8, "0");
  }
  return out;
}

/** One page of the listing after the cursor; `undefined` as `next` when the listing ends. */
export function claimPage(claimable: readonly ClaimableName[], after: string | undefined, limit: number, refuse: (field: string) => never): { names: ClaimableName[]; next: string | undefined } {
  let start = 0;
  if (after !== undefined) {
    const at = claimable.findIndex((c) => claimKey(c) === after);
    if (at < 0) return refuse("claimable.after");
    start = at + 1;
  }
  const names = claimable.slice(start, start + limit);
  const last = names[names.length - 1];
  return { names, next: last && start + limit < claimable.length ? claimKey(last) : undefined };
}
