// The cache of the mock's DNS node: what `GET /nodes/{id}/dns/cache` lists and
// `POST /nodes/{id}/dns/cache/flush` empties. Entries are kept in the canonical order of their
// names (RFC 4034: label by label from the root), then by type and view, as the server lists
// them; the cursor is the position after the last entry of a page. Shared by the msw handlers
// and the browser fakes of the end-to-end tests.
import type { components } from "../generated/schema";

type S = components["schemas"];
export type CacheEntry = S["DnsCacheEntry"];

export interface DnsCacheState {
  entries: CacheEntry[];
}

/** The view of the seeded entries that are not in the default view. */
export const CACHE_VIEW = "0190c3a2-5b7e-7000-8000-00000000c0de";

function entry(name: string, type: string, ttl: number, records: S["RecordData"][], extra: Partial<CacheEntry> = {}): CacheEntry {
  return {
    name,
    type: type as CacheEntry["type"],
    rcode: 0,
    ttl,
    stale: false,
    hits: 0,
    state: "unvalidated",
    records,
    ...extra,
  };
}

/** A signature of example.test over `covered`, valid from 2026-10-22 07:40 to 2026-11-12 02:08 UTC. */
function rrsig(covered: S["Rtype"], labels: number): S["RecordData"] {
  return {
    type: "RRSIG",
    type_covered: covered,
    algorithm: 13,
    labels,
    original_ttl: 300,
    expiration: Date.UTC(2026, 10, 12, 2, 8) / 1000,
    inception: Date.UTC(2026, 9, 22, 7, 40) / 1000,
    key_tag: 4711,
    signer: "example.test",
    signature: "3045022100c0ffee",
  };
}

export function seedDnsCache(): DnsCacheState {
  const entries = [
    entry("www.example.test", "A", 245, [
      { type: "CNAME", target: "cdn.example.test" },
      rrsig("CNAME", 3),
      { type: "A", address: "192.0.2.80" },
      rrsig("A", 3),
    ], { hits: 41, state: "secure", signature_expiry: "2026-11-01T00:00:00Z" }),
    entry("www.example.test", "AAAA", 245, [{ type: "AAAA", address: "2001:db8::80" }], { hits: 12 }),
    entry("example.test", "MX", 3_400, [{ type: "MX", preference: 10, exchange: "mail.example.test" }], { hits: 3 }),
    entry("missing.example.test", "A", 0, [], { rcode: 3, stale: true }),
    entry("intranet.example.test", "A", 60, [{ type: "A", address: "198.51.100.10" }], { view: CACHE_VIEW }),
    entry("example.net", "TXT", 12_000, [{ type: "TXT", strings: ["v=spf1 -all"] }]),
    entry("ns1.example.org", "AAAA", 900, [], { hits: 1, state: "bogus", ede: 6 }),
  ];
  return { entries: entries.sort(compare) };
}

function labels(name: string): string[] {
  return name === "." ? [] : name.split(".").reverse();
}

/** Canonical name order, then type and view (none first). */
export function compare(a: CacheEntry, b: CacheEntry): number {
  const la = labels(a.name);
  const lb = labels(b.name);
  for (let i = 0; i < Math.min(la.length, lb.length); i++) {
    const x = la[i] ?? "";
    const y = lb[i] ?? "";
    if (x !== y) return x < y ? -1 : 1;
  }
  if (la.length !== lb.length) return la.length - lb.length;
  if (a.type !== b.type) return a.type < b.type ? -1 : 1;
  return (a.view ?? "").localeCompare(b.view ?? "");
}

function within(name: string, suffix: string): boolean {
  return suffix === "." || name === suffix || name.endsWith(`.${suffix}`);
}

export class DnsCacheFailure extends Error {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super(message);
  }
}

/** A page: the entries at or below `suffix` in `view`, from `cursor`, at most `limit`. */
export function listCache(
  state: DnsCacheState,
  query: { suffix?: string | null; view?: string | null; limit?: string | null; cursor?: string | null },
  revision: number,
): S["Page_DnsCacheEntry"] {
  const limit = query.limit ? Number(query.limit) : 200;
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new DnsCacheFailure("limit", "limit must be between 1 and 1000");
  const suffix = (query.suffix ?? "").trim().toLowerCase().replace(/\.$/, "");
  const view = query.view ?? "";
  let start = 0;
  if (query.cursor) {
    const at = /^p(\d+)$/.exec(query.cursor);
    if (!at) throw new DnsCacheFailure("cursor", "the cursor is not valid");
    start = Number(at[1]);
  }
  const matching = state.entries.filter(
    (e) => (!suffix || within(e.name, suffix)) && (!view || (view === "default" ? !e.view : e.view === view)),
  );
  const items = matching.slice(start, start + limit);
  const next = start + limit < matching.length ? `p${start + limit}` : null;
  return { items, next_cursor: next, revision } as S["Page_DnsCacheEntry"];
}

/** Removes the entries at or below `suffix` (every entry without one); returns the count. */
export function flushCache(state: DnsCacheState, suffix: string | null | undefined): number {
  const name = (suffix ?? "").trim().toLowerCase().replace(/\.$/, "");
  const before = state.entries.length;
  state.entries = name ? state.entries.filter((e) => !within(e.name, name)) : [];
  return before - state.entries.length;
}
