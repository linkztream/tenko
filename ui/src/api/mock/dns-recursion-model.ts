// The recursive resolver of the mock's DNS node (WP10.1): what `GET /nodes/{id}/dns/recursion`
// reports (the hints, the last priming, the root servers with their round-trip times, the sizes
// of the infrastructure cache against their bounds, the work budget and the counters), the
// priming (`POST .../recursion/prime`) and the infrastructure cache (`GET .../infra`, a page of
// zone cuts in canonical name order, and `POST .../infra/flush`). Pure code without msw and
// without the mock database, shared with the browser fakes of the end-to-end tests.
import type { components } from "../generated/schema";

type S = components["schemas"];
export type RecursionStatus = S["RecursionStatus"];
export type InfraCut = S["InfraCutItem"];

export interface RecursionState {
  /** `false`: the node's resolver is off (`[dns.recursion] enabled`). */
  enabled: boolean;
  /** When the last priming ended; `null` before the first. */
  primedAt: string | null;
  /** Whether the last priming succeeded. */
  primingOk: boolean;
  /** Zone cuts of the infrastructure cache. */
  cuts: InfraCut[];
  /** Primings since the role started. */
  primings: number;
}

export class RecursionFailure extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
    readonly params: Record<string, string> = {},
  ) {
    super(message);
  }
}

const ROOT_SERVERS: ReadonlyArray<readonly [string, string, number]> = [
  ["a.root-servers.test", "192.0.2.1", 12.5],
  ["b.root-servers.test", "192.0.2.2", 31.25],
  ["c.root-servers.test", "2001:db8::3", 18],
];

function cut(zone: string, ns: string, address: string): InfraCut {
  return {
    zone,
    ds: "unknown",
    ttl: 3_600,
    servers: [
      {
        name: ns,
        addresses: [
          {
            address,
            origin: "glue",
            ttl: 3_600,
            srtt_ms: 21.5,
            p50_ms: 20,
            p99_ms: 64,
            failures: 0,
            down: false,
            edns: true,
            tcp_only: false,
            lame: false,
            lower_case: false,
            unwanted: 0,
          },
        ],
      },
    ],
  };
}

export function seedRecursion(): RecursionState {
  return {
    enabled: true,
    primedAt: "2026-10-17T11:58:02Z",
    primingOk: true,
    cuts: [
      cut("test", "a.nic.test", "192.0.2.53"),
      cut("example.test", "ns1.example.test", "192.0.2.10"),
      cut("sub.example.test", "ns.sub.example.test", "192.0.2.11"),
      cut("example.org", "ns.example.org", "198.51.100.7"),
    ],
    primings: 1,
  };
}

/** Canonical name order: label by label from the root (RFC 4034 section 6.1). */
function labels(name: string): string[] {
  return name === "." ? [] : name.split(".").reverse();
}

function compare(a: string, b: string): number {
  const la = labels(a);
  const lb = labels(b);
  for (let i = 0; i < Math.min(la.length, lb.length); i++) {
    const x = la[i] ?? "";
    const y = lb[i] ?? "";
    if (x !== y) return x < y ? -1 : 1;
  }
  return la.length - lb.length;
}

function within(name: string, suffix: string): boolean {
  return suffix === "" || suffix === "." || name === suffix || name.endsWith(`.${suffix}`);
}

/** The node's recursion status; a node without a resolver reads as off with empty fields. */
export function recursionStatus(state: RecursionState): RecursionStatus {
  if (!state.enabled) {
    return {
      enabled: false,
      hints_source: "",
      hints_date: "",
      root_servers: [],
      infra: { zones: 0, max_zones: 0, servers: 0, max_servers: 0, names: 0 },
      budget: { queries: 0, restarts: 0, depth: 0, attempts: 0, wall_ms: 0 },
      counters: counters(0),
      trust_anchors: [],
      problems: [],
    };
  }
  const status: RecursionStatus = {
    enabled: true,
    hints_source: "shipped",
    hints_date: "2026-01-31",
    root_servers: ROOT_SERVERS.map(([name, address, srtt]) => ({ name, address, srtt_ms: srtt })),
    infra: { zones: state.cuts.length, max_zones: 10_000, servers: state.cuts.length, max_servers: 50_000, names: state.cuts.length },
    budget: { queries: 32, restarts: 8, depth: 6, attempts: 3, wall_ms: 10_000 },
    counters: counters(state.primings),
    trust_anchors: [],
    problems: state.primedAt !== null && !state.primingOk ? ["priming_failed"] : [],
  };
  if (state.primedAt !== null) {
    status.last_priming = { at: state.primedAt, outcome: state.primingOk ? "ok" : "failed", duration_ms: 42.5 };
    status.root_expires_secs = 518_400;
  }
  return status;
}

function counters(primings: number): RecursionStatus["counters"] {
  const on = primings > 0 ? 1 : 0;
  return {
    answered: 1_204 * on,
    servfail: 17 * on,
    budget: 2 * on,
    timeout: 3 * on,
    local: 88 * on,
    failure_cache_hits: 9 * on,
    joined: 41 * on,
    subqueries: 5_310 * on,
    budget_queries: 1 * on,
    budget_restarts: 0,
    budget_depth: 1 * on,
    budget_time: 3 * on,
    primings_ok: primings,
    primings_failed: 0,
    unwanted: 6 * on,
    unwanted_flushes: 0,
    secure: 0,
    insecure: 0,
    bogus: 0,
    indeterminate: 0,
  };
}

function disabled(): RecursionFailure {
  return new RecursionFailure("dns.recursion.disabled", 409, "the recursive resolver of node 1 is off", { node: "1" });
}

/** `dns.recursion.prime`: a priming ends now and succeeds. */
export function primeNow(state: RecursionState, now: number): void {
  if (!state.enabled) throw disabled();
  state.primedAt = new Date(now).toISOString();
  state.primingOk = true;
  state.primings += 1;
}

const NAME = /^[a-z0-9_*.-]+\.?$/i;

function suffixOf(raw: string | null | undefined, field: string): string {
  const text = (raw ?? "").trim().toLowerCase();
  if (text !== "" && (!NAME.test(text) || text.includes(".."))) {
    throw new RecursionFailure("sys.invalid_value", 400, `${field}: \`${raw}\` is not a DNS name`, { field });
  }
  return text.replace(/\.$/, "");
}

/** `dns.infra.list`: a page of zone cuts in canonical order; the cursor is the zone before the page. */
export function listInfra(
  state: RecursionState,
  query: { suffix?: string | null; limit?: string | null; cursor?: string | null },
  revision: number,
): S["Page_InfraCutItem"] {
  const limit = query.limit ? Number(query.limit) : 200;
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    throw new RecursionFailure("sys.invalid_value", 400, "limit must be between 1 and 1000", { field: "limit" });
  }
  const suffix = suffixOf(query.suffix, "suffix");
  const after = query.cursor ? suffixOf(query.cursor, "cursor") : "";
  if (!state.enabled) throw disabled();
  const matching = [...state.cuts]
    .sort((a, b) => compare(a.zone, b.zone))
    .filter((c) => within(c.zone, suffix) && (after === "" || compare(c.zone, after) > 0));
  const items = matching.slice(0, limit);
  const last = items[items.length - 1];
  const next = items.length === limit && last ? last.zone : null;
  return { items, next_cursor: next, revision } as S["Page_InfraCutItem"];
}

/** `dns.infra.flush`: drops the cuts at or below `suffix` (all without one); returns the count. */
export function flushInfra(state: RecursionState, raw: string | null | undefined): number {
  const suffix = suffixOf(raw, "suffix");
  if (!state.enabled) throw disabled();
  const before = state.cuts.length;
  state.cuts = suffix ? state.cuts.filter((c) => !within(c.zone, suffix)) : [];
  return before - state.cuts.length;
}
