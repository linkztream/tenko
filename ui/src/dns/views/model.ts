// The pure helpers of the views page (DNS-20, docs/dns.md section 11): the six tests of a view
// in their typed form (the rule editor keeps one draft per rule: a list of values, the
// transports, or a time window), the checks the server makes before it answers
// `dns.view.invalid`, the scope map with its weights and the share each weight gives, and the
// positions of a reorder. No translated text here; the page maps the problems to words.
import type { components } from "../../api/generated/schema";
import { parseCidr, parseIp } from "../../ipam/ip";
import { canonical, splitList, validName } from "../model";

type S = components["schemas"];
export type MatchRule = S["MatchRule"];
export type RuleKind = MatchRule["test"];
export type QueryTransport = S["QueryTransport"];
export type ScopeWeight = S["ScopeWeight"];

/** The tests in the order the editor offers them. */
export const RULE_KINDS: readonly RuleKind[] = ["client_subnet", "transport", "interface", "qtype", "qname", "time_of_day"];

export const QUERY_TRANSPORTS: readonly QueryTransport[] = ["udp", "tcp", "dot", "doh"];

/** The limits of the view service (docs/dns.md section 11). */
export const MAX_RULES = 32;
export const MAX_VALUES = 1_000;
export const MAX_SCOPES = 256;
export const MAX_WEIGHT = 1_000;
export const MAX_NAME = 64;
export const MAX_DESCRIPTION = 1_000;

/** A record type as the server takes it: a mnemonic or `TYPEnnn`. */
const RTYPE = /^([A-Z][A-Z0-9-]{0,15}|TYPE\d{1,5})$/;

/** The values of a rule as text, in order (a time window has none). */
export function ruleValues(rule: MatchRule): string[] {
  switch (rule.test) {
    case "client_subnet":
      return rule.prefixes;
    case "transport":
      return rule.transports;
    case "interface":
      return rule.addresses;
    case "qtype":
      return rule.types;
    case "qname":
      return rule.suffixes;
    case "time_of_day":
      return [];
  }
}

/** A minute of the day as `HH:MM`. */
export function minuteText(minute: number): string {
  const h = Math.floor(minute / 60);
  const m = minute % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

/** A minute of the day from `HH:MM` (or `H:MM`); `null` when it is not a time of day. */
export function parseMinute(text: string): number | null {
  const match = /^(\d{1,2}):(\d{2})$/.exec(text.trim());
  if (!match) return null;
  const h = Number(match[1]);
  const m = Number(match[2]);
  return h < 24 && m < 60 ? h * 60 + m : null;
}

/** One rule as the editor holds it. */
export interface RuleDraft {
  kind: RuleKind;
  /** The values of a list rule, typed with commas, spaces or new lines. */
  text: string;
  /** The transports of a transport rule. */
  transports: QueryTransport[];
  /** The window of a time rule, `HH:MM`. */
  from: string;
  to: string;
}

export function emptyDraft(kind: RuleKind): RuleDraft {
  return { kind, text: "", transports: kind === "transport" ? ["dot", "doh"] : [], from: kind === "time_of_day" ? "08:00" : "", to: kind === "time_of_day" ? "17:00" : "" };
}

export function draftOf(rule: MatchRule): RuleDraft {
  const draft = emptyDraft(rule.test);
  if (rule.test === "transport") return { ...draft, transports: [...rule.transports] };
  if (rule.test === "time_of_day") return { ...draft, from: minuteText(rule.from_minute), to: minuteText(rule.to_minute) };
  return { ...draft, text: ruleValues(rule).join("\n") };
}

export type RuleProblem =
  | { problem: "empty" }
  | { problem: "too_many" }
  | { problem: "prefix" | "address" | "type" | "name"; entry: string }
  | { problem: "time"; entry: string };

export type ParsedRule = { ok: true; rule: MatchRule } | ({ ok: false } & RuleProblem);

/** A draft as the rule the server takes, or its first problem. */
export function parseRule(draft: RuleDraft): ParsedRule {
  if (draft.kind === "transport") {
    const transports = QUERY_TRANSPORTS.filter((tr) => draft.transports.includes(tr));
    return transports.length > 0 ? { ok: true, rule: { test: "transport", transports } } : { ok: false, problem: "empty" };
  }
  if (draft.kind === "time_of_day") {
    const from = parseMinute(draft.from);
    if (from === null) return { ok: false, problem: "time", entry: draft.from };
    const to = parseMinute(draft.to);
    if (to === null) return { ok: false, problem: "time", entry: draft.to };
    return { ok: true, rule: { test: "time_of_day", from_minute: from, to_minute: to } };
  }
  const values = [...new Set(splitList(draft.text))];
  if (values.length === 0) return { ok: false, problem: "empty" };
  if (values.length > MAX_VALUES) return { ok: false, problem: "too_many" };
  switch (draft.kind) {
    case "client_subnet": {
      const bad = values.find((v) => !parseCidr(v));
      return bad === undefined ? { ok: true, rule: { test: "client_subnet", prefixes: values.map((v) => v.toLowerCase()) } } : { ok: false, problem: "prefix", entry: bad };
    }
    case "interface": {
      const bad = values.find((v) => !parseIp(v));
      return bad === undefined ? { ok: true, rule: { test: "interface", addresses: values.map((v) => v.toLowerCase()) } } : { ok: false, problem: "address", entry: bad };
    }
    case "qtype": {
      const types = values.map((v) => v.toUpperCase());
      const bad = types.find((v) => !RTYPE.test(v));
      return bad === undefined ? { ok: true, rule: { test: "qtype", types } } : { ok: false, problem: "type", entry: bad };
    }
    case "qname": {
      const names = values.map(canonical);
      const bad = names.find((v) => !validName(v));
      return bad === undefined ? { ok: true, rule: { test: "qname", suffixes: names } } : { ok: false, problem: "name", entry: bad };
    }
  }
}

/** One entry of the scope map as the editor holds it. */
export interface ScopeDraft {
  zone: string;
  scope: string;
  weight: string;
}

export type ScopeProblem = { index: number; problem: "zone" | "weight" | "twice" };

export type ParsedScopes = { ok: true; map: ScopeWeight[] } | ({ ok: false } & ScopeProblem);

/** The scope map from its drafts, or the first problem (a missing zone, a weight out of 1 to 1000, a scope twice). */
export function parseScopes(drafts: readonly ScopeDraft[]): ParsedScopes {
  const map: ScopeWeight[] = [];
  for (const [index, d] of drafts.entries()) {
    if (!d.zone || !d.scope) return { ok: false, index, problem: "zone" };
    const weight = Number(d.weight.trim());
    if (!/^\d+$/.test(d.weight.trim()) || weight < 1 || weight > MAX_WEIGHT) return { ok: false, index, problem: "weight" };
    if (map.some((m) => m.zone === d.zone && m.scope === d.scope)) return { ok: false, index, problem: "twice" };
    map.push({ zone: d.zone, scope: d.scope, weight });
  }
  return { ok: true, map };
}

/**
 * The share of each entry among the entries of its zone, in whole per cent (the split a
 * client population sees: each client gets one scope of the zone, chosen by a hash of its
 * address in proportion to the weights).
 */
export function shares(map: readonly ScopeWeight[]): number[] {
  const totals = new Map<string, number>();
  for (const m of map) totals.set(m.zone, (totals.get(m.zone) ?? 0) + m.weight);
  return map.map((m) => {
    const total = totals.get(m.zone) ?? 0;
    return total > 0 ? Math.round((m.weight * 100) / total) : 0;
  });
}

export type ViewField = "name" | "rules" | "scope_map" | "description";

export interface ViewInput {
  name: string;
  rules: readonly RuleDraft[];
  scopes: readonly ScopeDraft[];
  description: string;
}

export type ViewProblem =
  | { field: "name"; problem: "required" | "long" }
  | ({ field: "rules"; index: number } & RuleProblem)
  | { field: "rules"; index: -1; problem: "too_many_rules" }
  | ({ field: "scope_map" } & ScopeProblem)
  | { field: "scope_map"; index: -1; problem: "too_many_scopes" }
  | { field: "description"; problem: "long" };

export type CheckedView =
  | { ok: true; name: string; rules: MatchRule[]; scopeMap: ScopeWeight[]; description: string }
  | { ok: false; problems: ViewProblem[] };

/** The checks of a view before it is sent, every field's first problem. */
export function checkView(input: ViewInput): CheckedView {
  const problems: ViewProblem[] = [];
  const name = input.name.trim();
  if (name === "") problems.push({ field: "name", problem: "required" });
  else if ([...name].length > MAX_NAME) problems.push({ field: "name", problem: "long" });
  const rules: MatchRule[] = [];
  if (input.rules.length > MAX_RULES) problems.push({ field: "rules", index: -1, problem: "too_many_rules" });
  else {
    for (const [index, draft] of input.rules.entries()) {
      const parsed = parseRule(draft);
      if (parsed.ok) rules.push(parsed.rule);
      else {
        const { ok: _ok, ...problem } = parsed;
        problems.push({ field: "rules", index, ...problem });
        break;
      }
    }
  }
  let scopeMap: ScopeWeight[] = [];
  if (input.scopes.length > MAX_SCOPES) problems.push({ field: "scope_map", index: -1, problem: "too_many_scopes" });
  else {
    const parsed = parseScopes(input.scopes);
    if (parsed.ok) scopeMap = parsed.map;
    else problems.push({ field: "scope_map", index: parsed.index, problem: parsed.problem });
  }
  const description = input.description.trim();
  if ([...description].length > MAX_DESCRIPTION) problems.push({ field: "description", problem: "long" });
  return problems.length > 0 ? { ok: false, problems } : { ok: true, name, rules, scopeMap, description };
}

/** The views in the order they are tried: `order`, then the identifier. */
export function viewOrder(a: { order: number; id: string }, b: { order: number; id: string }): number {
  return a.order - b.order || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/**
 * The position (from 1) a view moves to when it goes `delta` places up (negative) or down
 * among `views` (in order); `undefined` when it is at that end already.
 */
export function movedTo(views: readonly { id: string }[], id: string, delta: -1 | 1): number | undefined {
  const index = views.findIndex((v) => v.id === id);
  const target = index + delta;
  if (index < 0 || target < 0 || target >= views.length) return undefined;
  return target + 1;
}

/** The position a drag of view `id` onto view `onto` asks for (the dragged view takes its place). */
export function droppedAt(views: readonly { id: string }[], id: string, onto: string): number | undefined {
  const from = views.findIndex((v) => v.id === id);
  const to = views.findIndex((v) => v.id === onto);
  if (from < 0 || to < 0 || from === to) return undefined;
  return to + 1;
}
