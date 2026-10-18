// The views of the mock DNS service (WP6.4, DNS-20) as pure state and functions, with the
// rules of the server's view service (docs/dns.md section 11): a unique name, the six tests,
// a scope map whose zones have the scopes named, weights 1 to 1000, a recursion access list
// that exists, positions from 1 without gaps (a view created or moved to a position pushes the
// others down, a deleted one closes its gap), and the in-use rules in both directions: a view
// a forwarding rule names cannot be deleted, a zone scope or a zone a view names cannot be
// removed, an access list a view names for recursion is in use. No msw and no mock database
// here; the caller passes the clock, the revision and new ids. Failures are `DnsFailure` with
// the codes of docs/dns-contracts.md section 5. Documentation values only.
import type { components } from "../generated/schema";
import { parseCidr, parseIp } from "../../ipam/ip";
import { canonical, validName } from "../../dns/model";
import { DNS_IDS, DnsFailure, type DnsContext, type DnsState } from "./dns-model";
import type { ResolverState } from "./dns-resolver-model";

type S = components["schemas"];
export type MockView = S["ViewItem"];

export interface ViewsState {
  views: MockView[];
}

/** The fixed identifiers of the seed, for tests. */
export const VIEW_IDS = {
  office: "0190d1c2-0000-7000-8000-00000000de01",
  tls: "0190d1c2-0000-7000-8000-00000000de02",
} as const;

/** The scopes the seed adds to example.test besides `default`. */
export const SEED_SCOPES = ["internal", "external"] as const;

function fail(status: number, code: string, params: Record<string, string> = {}, detail?: string): never {
  throw new DnsFailure(status, code, params, detail);
}

function invalid(field: string, reason: string, params: Record<string, string> = {}): never {
  return fail(400, "dns.view.invalid", { field, reason, ...params }, `${field}: ${reason}`);
}

function textOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** The views of the seed: the office on its subnet sees the internal scope; DoT and DoH clients get a 700/300 split. */
export function seedViews(ctx: DnsContext, dns: DnsState): ViewsState {
  const revision = ctx.nextRevision();
  const example = dns.zones.find((z) => z.id === DNS_IDS.zone.example);
  if (example) {
    example.scopes = [{ name: "default", description: null }, ...SEED_SCOPES.map((name) => ({ name, description: null }))];
  }
  return {
    views: [
      {
        id: VIEW_IDS.office,
        name: "office",
        order: 1,
        rules: [{ test: "client_subnet", prefixes: ["192.0.2.0/24", "2001:db8:0:10::/64"] }],
        scope_map: [{ zone: DNS_IDS.zone.example, scope: "internal", weight: 1 }],
        recursion: null,
        description: "The office network",
        revision,
      },
      {
        id: VIEW_IDS.tls,
        name: "encrypted clients",
        order: 2,
        rules: [{ test: "transport", transports: ["dot", "doh"] }],
        scope_map: [
          { zone: DNS_IDS.zone.example, scope: "internal", weight: 700 },
          { zone: DNS_IDS.zone.example, scope: "external", weight: 300 },
        ],
        recursion: null,
        description: null,
        revision,
      },
    ],
  };
}

export function listViews(state: ViewsState): MockView[] {
  return [...state.views].sort((a, b) => a.order - b.order || (a.id < b.id ? -1 : 1));
}

export function findView(state: ViewsState, id: string): MockView {
  return state.views.find((v) => v.id === id) ?? fail(404, "dns.view.not_found", { id }, `view ${id} does not exist`);
}

const TRANSPORTS = ["udp", "tcp", "dot", "doh"];
const RTYPE = /^([A-Z][A-Z0-9-]{0,15}|TYPE\d{1,5})$/;

function list(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) return invalid("rules", "a rule lists at least one value");
  if (value.length > 1_000) return invalid("rules", "a rule lists at most 1000 values");
  return value.map((v) => (typeof v === "string" ? v : invalid("rules", "values are text")));
}

function checkRule(raw: unknown): S["MatchRule"] {
  const r = (raw ?? {}) as Record<string, unknown>;
  switch (r.test) {
    case "client_subnet": {
      const prefixes = list(r.prefixes);
      if (prefixes.some((p) => !parseCidr(p))) fail(400, "sys.invalid_request", {}, "not a prefix");
      return { test: "client_subnet", prefixes };
    }
    case "transport": {
      const transports = list(r.transports);
      if (transports.some((tr) => !TRANSPORTS.includes(tr))) fail(400, "sys.invalid_request", {}, "unknown transport");
      return { test: "transport", transports: transports as S["QueryTransport"][] };
    }
    case "interface": {
      const addresses = list(r.addresses);
      if (addresses.some((a) => !parseIp(a))) fail(400, "sys.invalid_request", {}, "not an address");
      return { test: "interface", addresses };
    }
    case "qtype": {
      const types = list(r.types).map((x) => x.toUpperCase());
      if (types.some((x) => !RTYPE.test(x))) fail(400, "sys.invalid_request", {}, "not a type");
      return { test: "qtype", types };
    }
    case "qname": {
      const suffixes = list(r.suffixes).map(canonical);
      if (suffixes.some((n) => !validName(n))) fail(400, "sys.invalid_request", {}, "not a name");
      return { test: "qname", suffixes };
    }
    case "time_of_day": {
      const from = r.from_minute;
      const to = r.to_minute;
      if (typeof from !== "number" || typeof to !== "number") return fail(400, "sys.invalid_request", {}, "minutes are numbers");
      if (from >= 1440 || to >= 1440 || from < 0 || to < 0) return invalid("rules", "minutes of the day are 0 to 1439");
      return { test: "time_of_day", from_minute: from, to_minute: to };
    }
    default:
      return fail(400, "sys.invalid_request", {}, "unknown test");
  }
}

/** The view's checks against itself and the other rows (the zones, the lists, the other views). */
function checkView(state: ViewsState, dns: DnsState, view: MockView): void {
  const name = view.name;
  if (name.trim() !== name || name === "" || [...name].length > 64) invalid("name", "1 to 64 characters without surrounding spaces");
  if (state.views.some((v) => v.id !== view.id && v.name.toLowerCase() === name.toLowerCase())) invalid("name", "a view of this name exists");
  if ((view.rules ?? []).length > 32) invalid("rules", "a view has at most 32 rules");
  const map = view.scope_map ?? [];
  if (map.length > 256) invalid("scope_map", "a view maps at most 256 zone scopes");
  for (const [i, entry] of map.entries()) {
    if (!Number.isInteger(entry.weight) || entry.weight < 1 || entry.weight > 1000) invalid("scope_map", "weights are 1 to 1000");
    if (map.slice(0, i).some((m) => m.zone === entry.zone && m.scope === entry.scope)) invalid("scope_map", "a zone scope appears twice");
    const zone = dns.zones.find((z) => z.id === entry.zone);
    if (!zone) invalid("scope_map", "the zone does not exist", { zone: entry.zone });
    if (!(zone.scopes ?? []).some((s) => s.name === entry.scope)) invalid("scope_map", "the zone has no such scope", { zone: zone.name, scope: entry.scope });
  }
  if (view.recursion && !dns.acls.some((a) => a.id === view.recursion)) invalid("recursion", "the access list does not exist", { acl: view.recursion });
  if ((view.description ?? "").length > 1000) invalid("description", "at most 1000 characters");
}

/** Puts `view` at `position` (from 1, clamped) among the other views and numbers them all from 1. */
function place(state: ViewsState, view: MockView, position: number, revision: number): void {
  const others = listViews(state).filter((v) => v.id !== view.id);
  const index = Math.max(0, Math.min(others.length, Math.trunc(position) - 1));
  others.splice(index, 0, view);
  state.views = others.map((v, i) => (v === view ? { ...v, order: i + 1, revision } : v.order === i + 1 ? v : { ...v, order: i + 1, revision }));
}

export function createView(state: ViewsState, ctx: DnsContext, dns: DnsState, body: Record<string, unknown>): MockView {
  if (typeof body.order !== "number") fail(400, "sys.invalid_request", {}, "order is required");
  const view: MockView = {
    id: ctx.newId(),
    name: typeof body.name === "string" ? body.name : "",
    rules: Array.isArray(body.rules) ? body.rules.map(checkRule) : [],
    scope_map: Array.isArray(body.scope_map) ? (body.scope_map as S["ScopeWeight"][]) : [],
    order: body.order,
    recursion: typeof body.recursion === "string" ? body.recursion : null,
    description: textOrNull(body.description),
    revision: 0,
  };
  checkView(state, dns, view);
  const revision = ctx.nextRevision();
  view.revision = revision;
  place(state, view, view.order, revision);
  return findView(state, view.id);
}

export function updateView(
  state: ViewsState,
  ctx: DnsContext,
  dns: DnsState,
  id: string,
  body: Record<string, unknown>,
  ifMatch: number | "*" | null,
): MockView {
  const current = findView(state, id);
  if (typeof ifMatch === "number" && ifMatch !== current.revision) {
    fail(412, "sys.store.precondition_failed", {}, "the view changed since it was read; reload and retry");
  }
  const next: MockView = { ...current };
  if (typeof body.name === "string") next.name = body.name;
  if (Array.isArray(body.rules)) next.rules = body.rules.map(checkRule);
  if (Array.isArray(body.scope_map)) next.scope_map = body.scope_map as S["ScopeWeight"][];
  if (body.default_recursion === true) next.recursion = null;
  else if (typeof body.recursion === "string") next.recursion = body.recursion;
  if (body.description !== undefined) next.description = textOrNull(body.description);
  checkView(state, dns, next);
  const position = typeof body.order === "number" ? body.order : listViews(state).findIndex((v) => v.id === id) + 1;
  place(state, next, position, ctx.nextRevision());
  return findView(state, id);
}

export function deleteView(state: ViewsState, ctx: DnsContext, resolver: ResolverState, id: string, ifMatch: number | "*" | null): MockView {
  const view = findView(state, id);
  if (typeof ifMatch === "number" && ifMatch !== view.revision) {
    fail(412, "sys.store.precondition_failed", {}, "the view changed since it was read; reload and retry");
  }
  const by = resolver.forwarders
    .filter((r) => r.view === id)
    .map((r) => `forwarder:${r.suffix}`)
    .sort();
  if (by.length > 0) fail(409, "dns.view.in_use", { id, by: by.join(",") }, `view ${view.name} is named by ${by.join(", ")}`);
  const revision = ctx.nextRevision();
  state.views = listViews(state)
    .filter((v) => v.id !== id)
    .map((v, i) => (v.order === i + 1 ? v : { ...v, order: i + 1, revision }));
  return view;
}

/** The views that name a scope of a zone (any scope when `scopes` is absent), as `view:<name>`. */
export function viewsNaming(state: ViewsState, zone: string, scopes?: readonly string[]): string[] {
  return state.views
    .filter((v) => (v.scope_map ?? []).some((m) => m.zone === zone && (scopes === undefined || scopes.includes(m.scope))))
    .map((v) => `view:${v.name}`)
    .sort();
}

/** The views that name an access list for recursion, as `view:<name>`. */
export function viewsUsingAcl(state: ViewsState, acl: string): string[] {
  return state.views
    .filter((v) => v.recursion === acl)
    .map((v) => `view:${v.name}`)
    .sort();
}

/**
 * The view side of a zone change or deletion: refuses removing a scope a view names (`after`
 * the scopes the change keeps; `undefined` for the deletion), as the server does.
 */
export function checkZoneScopes(state: ViewsState, zone: { id: string; name: string; scopes?: readonly { name: string }[] | null }, after?: readonly string[]): void {
  const removed = (zone.scopes ?? []).map((s) => s.name).filter((name) => after === undefined || !after.includes(name));
  for (const scope of removed) {
    const by = viewsNaming(state, zone.id, [scope]);
    if (by.length > 0) {
      fail(409, "dns.view.in_use", { id: zone.id, by: by.join(","), zone: zone.name, scope }, `${after ? `scope ${scope} of ` : ""}zone ${zone.name} is named by ${by.join(", ")}`);
    }
  }
}
