// The resolver side of the mock DNS service (WP5.5) as pure state and functions: forwarding
// rules (docs/dns-resolver.md section 2.1) and block lists with their compiled versions (WP5.2,
// the routes of docs/dns-contracts.md section 3 and the file upload the lead granted,
// `PUT /dns/lists/{id}/file`), and the resolver figures of the node status (the cache and the
// problems). No msw and no mock database here, so the end-to-end fakes run the same code as
// the msw handlers (routes-dns.ts); the caller passes the clock, the revision and new ids.
// Failures are `DnsFailure` with the codes of docs/dns-contracts.md section 5. Documentation
// values only: names under example.test, addresses of RFC 5737 and RFC 3849.
import type { components } from "../generated/schema";
import { parseIp } from "../../ipam/ip";
import { canonical, validName } from "../../dns/model";
import { DnsFailure, type DnsContext } from "./dns-model";

type S = components["schemas"];
export type MockForwarder = S["ForwarderItem"];
export type MockListVersion = S["ListVersionItem"] & { etag?: string | null };
export type MockList = Omit<S["ListItem"], "version"> & { version?: MockListVersion | null };

export interface ResolverState {
  forwarders: MockForwarder[];
  lists: MockList[];
  /** The names a fetch of a URL list finds, by URL; a URL not here fails with `dns.list.fetch_failed`. */
  sources: Map<string, string>;
  /** The figures of the node status. */
  cache: { entries: number; bytes: number; hits: number; misses: number; stale: number };
  problems: string[];
}

/** The fixed identifiers of the seed, for tests. */
export const RESOLVER_IDS = {
  forwarder: {
    corp: "0190d1c2-0000-7000-8000-00000000dc01",
  },
  list: {
    ads: "0190d1c2-0000-7000-8000-00000000dd01",
    local: "0190d1c2-0000-7000-8000-00000000dd02",
  },
} as const;

/** The URL the seeded list is fetched from, and a second one tests may use. */
export const LIST_URLS = {
  ads: "https://lists.example.test/ads.txt",
  trackers: "https://lists.example.test/trackers.txt",
} as const;

function fail(status: number, code: string, params: Record<string, string> = {}, detail?: string): never {
  throw new DnsFailure(status, code, params, detail);
}

function invalidRule(field: string, reason: string): never {
  return fail(400, "dns.forwarder.invalid", { field, reason }, `${field}: ${reason}`);
}

function invalidList(field: string, reason: string): never {
  return fail(400, "dns.list.invalid", { field, reason }, `${field}: ${reason}`);
}

function stale(what: string): never {
  return fail(412, "sys.store.precondition_failed", {}, `the ${what} changed since it was read; reload and retry`);
}

export function seedResolver(ctx: DnsContext): ResolverState {
  const revision = ctx.nextRevision();
  const now = ctx.now();
  return {
    forwarders: [
      {
        id: RESOLVER_IDS.forwarder.corp,
        suffix: "corp.example.test",
        transport: "plain",
        upstreams: [{ address: "192.0.2.10" }, { address: "192.0.2.11" }],
        tls_name: null,
        view: null,
        description: "The domain controllers",
        revision,
      },
    ],
    lists: [
      {
        id: RESOLVER_IDS.list.ads,
        name: "Ads",
        source: { kind: "url", url: LIST_URLS.ads },
        format: "domains",
        action: { kind: "nxdomain" },
        enabled: true,
        interval_hours: 24,
        description: null,
        revision,
        last_error: null,
        version: { revision: 3, entries: 4, fetched: new Date(now - 3_600_000).toISOString(), etag: '"a1b2c3"' },
      },
      {
        id: RESOLVER_IDS.list.local,
        name: "Local",
        source: { kind: "upload" },
        format: "hosts",
        action: { kind: "redirect", address: "192.0.2.80" },
        enabled: false,
        interval_hours: 0,
        description: "Names blocked by hand",
        revision,
        last_error: null,
        version: null,
      },
    ],
    sources: new Map([
      [LIST_URLS.ads, "ads.example.test\ntrack.example.test\npixel.example.test\nbanner.example.test\nnew.example.test\n"],
      [LIST_URLS.trackers, "# trackers\nt1.example.test\nt2.example.test\n"],
    ]),
    cache: { entries: 1_234, bytes: 2_097_152, hits: 8_400, misses: 1_600, stale: 12 },
    problems: [],
  };
}

// ---------------------------------------------------------------------------------
// Forwarding rules

const TRANSPORTS = ["plain", "dot", "doh"] as const;

function checkUpstreams(value: unknown, transport: S["ForwardTransport"]): S["Upstream"][] {
  if (!Array.isArray(value) || value.length === 0) return invalidRule("upstreams", "at least one upstream");
  if (value.length > 16) return invalidRule("upstreams", "at most 16 upstreams");
  return value.map((raw) => {
    const u = (raw ?? {}) as Record<string, unknown>;
    const address = typeof u.address === "string" ? u.address : "";
    if (!parseIp(address)) return invalidRule("upstreams", `not an address: ${address}`);
    const out: S["Upstream"] = { address };
    if (u.port !== undefined && u.port !== null) {
      if (typeof u.port !== "number" || u.port < 1 || u.port > 65_535) return invalidRule("upstreams", "port 0 or out of range");
      out.port = u.port;
    }
    if (u.path !== undefined && u.path !== null) {
      if (transport !== "doh") return invalidRule("upstreams", "a path needs DoH");
      if (typeof u.path !== "string" || !u.path.startsWith("/")) return invalidRule("upstreams", "a path starts with /");
      out.path = u.path;
    }
    return out;
  });
}

function checkRule(state: ResolverState, rule: MockForwarder): void {
  if (!validName(rule.suffix) || rule.suffix.includes("*")) invalidRule("suffix", "not a DNS name");
  const transport = rule.transport ?? "plain";
  if (transport !== "plain" && !rule.tls_name) invalidRule("tls_name", "DoT and DoH need tls_name");
  if (rule.view) invalidRule("view", "no such view");
  if (state.forwarders.some((other) => other.id !== rule.id && other.suffix === rule.suffix && (other.view ?? null) === (rule.view ?? null))) {
    invalidRule("suffix", "a rule for this suffix exists in this view");
  }
}

function transportOf(value: unknown): S["ForwardTransport"] {
  if (value === undefined || value === null) return "plain";
  if (typeof value !== "string" || !TRANSPORTS.includes(value as never)) return invalidRule("transport", "unknown transport");
  return value as S["ForwardTransport"];
}

function textOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** The rules by suffix with the root first, as the server lists them. */
export function listForwarders(state: ResolverState): MockForwarder[] {
  const rank = (r: MockForwarder) => (r.suffix === "." ? "" : r.suffix.split(".").reverse().join("."));
  return [...state.forwarders].sort((a, b) => (rank(a) < rank(b) ? -1 : rank(a) > rank(b) ? 1 : 0));
}

export function findForwarder(state: ResolverState, id: string): MockForwarder {
  return state.forwarders.find((r) => r.id === id) ?? fail(404, "dns.forwarder.not_found", { id });
}

export function createForwarder(state: ResolverState, ctx: DnsContext, body: Record<string, unknown>): MockForwarder {
  const transport = transportOf(body.transport);
  const rule: MockForwarder = {
    id: ctx.newId(),
    suffix: canonical(typeof body.suffix === "string" ? body.suffix : "") || ".",
    transport,
    upstreams: checkUpstreams(body.upstreams, transport),
    tls_name: textOrNull(body.tls_name),
    view: typeof body.view === "string" ? body.view : null,
    description: textOrNull(body.description),
    revision: 0,
  };
  checkRule(state, rule);
  rule.revision = ctx.nextRevision();
  state.forwarders.push(rule);
  return rule;
}

export function updateForwarder(
  state: ResolverState,
  ctx: DnsContext,
  id: string,
  body: Record<string, unknown>,
  ifMatch: number | "*" | null,
): MockForwarder {
  const current = findForwarder(state, id);
  if (typeof ifMatch === "number" && ifMatch !== current.revision) stale("forwarding rule");
  const next: MockForwarder = { ...current };
  if (typeof body.suffix === "string") next.suffix = canonical(body.suffix) || ".";
  if (body.transport !== undefined && body.transport !== null) next.transport = transportOf(body.transport);
  if (body.upstreams !== undefined && body.upstreams !== null) next.upstreams = checkUpstreams(body.upstreams, next.transport ?? "plain");
  if (body.tls_name !== undefined) next.tls_name = textOrNull(body.tls_name);
  if (body.description !== undefined) next.description = textOrNull(body.description);
  if (body.all_views === true) next.view = null;
  else if (typeof body.view === "string") next.view = body.view;
  checkRule(state, next);
  next.revision = ctx.nextRevision();
  state.forwarders = state.forwarders.map((r) => (r.id === id ? next : r));
  return next;
}

export function deleteForwarder(state: ResolverState, id: string, ifMatch: number | "*" | null): MockForwarder {
  const rule = findForwarder(state, id);
  if (typeof ifMatch === "number" && ifMatch !== rule.revision) stale("forwarding rule");
  state.forwarders = state.forwarders.filter((r) => r.id !== id);
  return rule;
}

// ---------------------------------------------------------------------------------
// Block lists

const FORMATS = ["hosts", "domains"] as const;

function checkSource(value: unknown): S["ListSource"] {
  const s = (value ?? {}) as Record<string, unknown>;
  if (s.kind === "upload") return { kind: "upload" };
  if (s.kind === "url" && typeof s.url === "string" && /^https?:\/\/[^/\s]+/i.test(s.url)) return { kind: "url", url: s.url };
  return invalidList("source", "a URL list needs an https:// or http:// URL");
}

function checkAction(value: unknown): S["BlockAction"] {
  const a = (value ?? {}) as Record<string, unknown>;
  if (a.kind === "nxdomain" || a.kind === "nodata") return { kind: a.kind };
  if (a.kind === "redirect" && typeof a.address === "string" && parseIp(a.address)) return { kind: "redirect", address: a.address };
  return invalidList("action", "unknown action or not an address");
}

function checkFormat(value: unknown): S["ListFormat"] {
  if (typeof value === "string" && FORMATS.includes(value as never)) return value as S["ListFormat"];
  return invalidList("format", "hosts or domains");
}

function checkInterval(value: unknown, source: S["ListSource"]): number {
  if (source.kind === "upload") return 0;
  const hours = value === undefined || value === null ? 24 : value;
  if (typeof hours !== "number" || !Number.isInteger(hours) || hours < 1 || hours > 168) return invalidList("interval_hours", "1 to 168");
  return hours;
}

function checkName(state: ResolverState, value: unknown, id?: string): string {
  const name = typeof value === "string" ? value.trim() : "";
  if (name === "" || name.length > 64) return invalidList("name", "1 to 64 characters");
  if (state.lists.some((l) => l.id !== id && l.name.toLowerCase() === name.toLowerCase())) return invalidList("name", "a list of this name exists");
  return name;
}

export function listLists(state: ResolverState): MockList[] {
  return [...state.lists].sort((a, b) => a.name.localeCompare(b.name));
}

export function findList(state: ResolverState, id: string): MockList {
  return state.lists.find((l) => l.id === id) ?? fail(404, "dns.list.not_found", { id });
}

export function createList(state: ResolverState, ctx: DnsContext, body: Record<string, unknown>): MockList {
  const source = checkSource(body.source);
  const list: MockList = {
    id: ctx.newId(),
    name: checkName(state, body.name),
    source,
    format: checkFormat(body.format),
    action: checkAction(body.action),
    enabled: body.enabled !== false,
    interval_hours: checkInterval(body.interval_hours, source),
    description: textOrNull(body.description),
    revision: ctx.nextRevision(),
    last_error: null,
    version: null,
  };
  state.lists.push(list);
  return list;
}

export function updateList(state: ResolverState, ctx: DnsContext, id: string, body: Record<string, unknown>, ifMatch: number | "*" | null): MockList {
  const current = findList(state, id);
  if (typeof ifMatch === "number" && ifMatch !== current.revision) stale("block list");
  const next: MockList = { ...current };
  if (body.name !== undefined && body.name !== null) next.name = checkName(state, body.name, id);
  if (body.source !== undefined && body.source !== null) {
    next.source = checkSource(body.source);
    if (next.source.kind !== current.source.kind) invalidList("source", "the kind of the source does not change");
  }
  if (body.format !== undefined && body.format !== null) next.format = checkFormat(body.format);
  if (body.action !== undefined && body.action !== null) next.action = checkAction(body.action);
  if (typeof body.enabled === "boolean") next.enabled = body.enabled;
  if (body.interval_hours !== undefined) next.interval_hours = checkInterval(body.interval_hours, next.source);
  if (body.description !== undefined) next.description = textOrNull(body.description);
  next.revision = ctx.nextRevision();
  state.lists = state.lists.map((l) => (l.id === id ? next : l));
  return next;
}

export function deleteList(state: ResolverState, id: string, ifMatch: number | "*" | null): MockList {
  const list = findList(state, id);
  if (typeof ifMatch === "number" && ifMatch !== list.revision) stale("block list");
  state.lists = state.lists.filter((l) => l.id !== id);
  return list;
}

/** The names of a list file: one per line, `#` comments; a hosts line is `<address> <name>...`. */
export function compileNames(text: string, format: S["ListFormat"]): string[] {
  const names = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line === "") continue;
    const words = line.split(/\s+/);
    const candidates = format === "hosts" ? words.slice(1) : words.slice(0, 1);
    for (const word of candidates) {
      const name = canonical(word);
      if (name !== "" && name !== "localhost" && validName(name)) names.add(name);
    }
  }
  return [...names];
}

function newVersion(ctx: DnsContext, list: MockList, entries: number, etag: string | null): void {
  list.version = { revision: (list.version?.revision ?? 0) + 1, entries, fetched: new Date(ctx.now()).toISOString(), etag };
  list.last_error = null;
  list.revision = ctx.nextRevision();
}

/** Fetches a URL list now; the compiled version replaces the newest, or `last_error` says why not. */
export function fetchList(state: ResolverState, ctx: DnsContext, id: string): MockList {
  const list = findList(state, id);
  if (list.source.kind !== "url") return fail(409, "dns.list.invalid", { field: "source", reason: "the list is uploaded, not fetched" });
  const text = state.sources.get(list.source.url);
  if (text === undefined) {
    list.last_error = "dns.list.fetch_failed";
    list.revision = ctx.nextRevision();
    return list;
  }
  newVersion(ctx, list, compileNames(text, list.format).length, `"${text.length.toString(16)}"`);
  return list;
}

/** The file of an uploaded list, compiled into its next version. */
export function uploadList(state: ResolverState, ctx: DnsContext, id: string, text: string, ifMatch: number | "*" | null): MockList {
  const list = findList(state, id);
  if (typeof ifMatch === "number" && ifMatch !== list.revision) stale("block list");
  if (list.source.kind !== "upload") return fail(409, "dns.list.invalid", { field: "source", reason: "a URL list is fetched, not uploaded" });
  if (text.length > 64 * 1024 * 1024) return fail(413, "sys.invalid_request", { field: "file" }, "the file is too large");
  newVersion(ctx, list, compileNames(text, list.format).length, null);
  return list;
}

// ---------------------------------------------------------------------------------
// The node status

/** The resolver fields of `GET /nodes/{id}/dns`. */
export function resolverStatus(state: ResolverState): Partial<S["DnsNodeStatus"]> {
  const c = state.cache;
  const asked = c.hits + c.misses;
  return {
    cache_entries: c.entries,
    cache_bytes: c.bytes,
    cache_hits: c.hits,
    cache_misses: c.misses,
    cache_stale: c.stale,
    ...(asked > 0 ? { cache_hit_ratio: c.hits / asked } : {}),
    problems: [...state.problems],
  };
}
