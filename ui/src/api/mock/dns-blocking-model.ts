// The blocking view of the mock DNS node: the figures of its query log for 24 hours or 7 days
// (`GET /dns/blocking/stats`), the pause of the block lists (`POST` and `DELETE
// /dns/blocking/pause`, with an expiry the node ends by itself) and "allow" from the log
// (`POST /dns/blocking/allow`: a name goes to the allow list `allowed`, created the first time).
// Pure code without msw and without the mock database, shared with the browser fake of the
// end-to-end test (e2e/support/dns-blocking-mock.ts). Documentation values only: names under
// example.test, clients of RFC 5737.
import type { components } from "../generated/schema";
import { DnsLogFailure } from "./dns-log-model";

type S = components["schemas"];
export type BlockingStats = S["BlockingStats"];
export type BlockingPause = S["BlockingPause"];
export type BlockingAllowed = S["BlockingAllowed"];
type QueryLogLine = S["QueryLogLine"];

const HOUR = 3_600_000;

/** The fixed identifiers of the seed, for tests. */
export const BLOCKING_IDS = {
  /** A block list that exists (the "Ads" list of the resolver seed). */
  ads: "0190d1c2-0000-7000-8000-00000000dd01",
  /** A block list deleted since: the log still names its id. */
  gone: "0190d1c2-0000-7000-8000-00000000dd99",
  /** The allow list `allowed`, created by the first "allow". */
  allowed: "0190d1c2-0000-7000-8000-00000000dd0a",
} as const;

/** The name of the allow list the first "allow" creates. */
export const ALLOW_LIST_NAME = "allowed";

export interface BlockingState {
  /** The node's query log is off: the figures answer 409 `dns.blocking.log_off`. */
  logOff: boolean;
  /** What the log keeps of the client. */
  logClient: "pseudonym" | "address" | "hidden";
  /** Days the log keeps. */
  logDays: number;
  /** One query in this many is logged. */
  logSample: number;
  /** The log held more than one read looks at. */
  truncated: boolean;
  /** The pause in force. */
  paused: BlockingPause | null;
  /** The names allowed so far, in the order they were added. */
  allowed: string[];
  /** Whether the allow list `allowed` exists. */
  allowListExists: boolean;
  /** The seeded names of the "top blocked" list (the first is the busiest). */
  blockedNames: string[];
}

export function seedBlocking(): BlockingState {
  return {
    logOff: false,
    logClient: "pseudonym",
    logDays: 7,
    logSample: 1,
    truncated: false,
    paused: null,
    allowed: [],
    allowListExists: false,
    blockedNames: ["ads.example.test", "track.example.test", "pixel.example.test", "banner.example.test", "metrics.example.test"],
  };
}

/** A client of the seed: its address, the pseudonym of the day and the name IPAM records for it. */
interface SeedClient {
  address: string;
  pseudonym: string;
  name?: string;
  weight: number;
  blockedWeight: number;
}

const CLIENTS: readonly SeedClient[] = [
  { address: "192.0.2.10", pseudonym: "p:3f2a9c0d81b7e645", name: "laptop.example.test", weight: 40, blockedWeight: 30 },
  { address: "192.0.2.11", pseudonym: "p:9b1e44c2a07d3f18", name: "phone.example.test", weight: 30, blockedWeight: 50 },
  { address: "192.0.2.20", pseudonym: "p:c45d0e9f7a12b366", weight: 20, blockedWeight: 15 },
  { address: "2001:db8::20", pseudonym: "p:5d7a1c3e90f2b4a8", name: "tv.example.test", weight: 10, blockedWeight: 5 },
];

const NAMES: readonly (readonly [string, number])[] = [
  ["www.example.test", 22],
  ["mail.example.test", 14],
  ["ads.example.test", 12],
  ["time.example.org", 9],
  ["track.example.test", 8],
  ["nas.example.test", 7],
  ["pixel.example.test", 5],
  ["printer.lab.example.test", 4],
  ["banner.example.test", 3],
  ["metrics.example.test", 2],
];

/** The hours of the last 7 days, oldest first, the last one the hour `now` is in. */
function hoursOf(now: number, count: number): BlockingStats["hours"] {
  const end = Math.floor(now / HOUR) * HOUR;
  const out: BlockingStats["hours"] = [];
  for (let i = count - 1; i >= 0; i--) {
    const start = end - i * HOUR;
    const hourOfDay = new Date(start).getUTCHours();
    // Quiet at night, busy in the evening; a little different every day.
    const day = Math.floor(start / (24 * HOUR));
    const wave = 0.55 + 0.45 * Math.sin(((hourOfDay - 9) / 24) * 2 * Math.PI);
    const queries = Math.round(40 + 260 * wave + (day % 5) * 7);
    const blocked = Math.round(queries * (0.18 + 0.12 * Math.abs(Math.sin(start / HOUR))));
    out.push({ start: new Date(start).toISOString(), queries, blocked });
  }
  return out;
}

function sum(values: readonly number[]): number {
  return values.reduce((a, b) => a + b, 0);
}

/** A share of `total` by weight, the rounding going to the first entry so that the parts add up. */
function split(total: number, weights: readonly number[]): number[] {
  const whole = sum(weights);
  const parts = weights.map((w) => Math.floor((total * w) / whole));
  parts[0] = (parts[0] ?? 0) + (total - sum(parts));
  return parts;
}

function paused(state: BlockingState, now: number): BlockingPause | null {
  const pause = state.paused;
  if (pause?.until && Date.parse(pause.until) <= now) state.paused = null;
  return state.paused;
}

/** The pause in force at `now`; the node ends a timed pause by itself. */
export function pausedNow(state: BlockingState, now: number): BlockingPause | null {
  return paused(state, now);
}

function clientOf(state: BlockingState, client: SeedClient, addresses: boolean): string | undefined {
  if (state.logClient === "hidden") return undefined;
  if (state.logClient === "address") return addresses ? client.address : undefined;
  return client.pseudonym;
}

/** The figures of a window as the node answers them. `addresses`: the caller may update the node. */
export function blockingStats(state: BlockingState, window: "24h" | "7d", top: number, addresses: boolean, now: number): BlockingStats {
  if (state.logOff) {
    throw new DnsLogFailure("dns.blocking.log_off", 409, "the query log is off on this node", { node: "1" });
  }
  const hours = hoursOf(now, window === "7d" ? 168 : 24);
  const queries = sum(hours.map((h) => h.queries));
  const blocked = sum(hours.map((h) => h.blocked));
  const cached = Math.round(queries * 0.42);

  const [adsBlocked = 0, goneBlocked = 0] = split(blocked, [82, 18]);
  const lists: BlockingStats["lists"] = [
    { list: BLOCKING_IDS.ads, name: "Ads", blocked: adsBlocked },
    { list: BLOCKING_IDS.gone, blocked: goneBlocked },
  ];

  const blockedCounts = split(blocked, state.blockedNames.map((_, i) => 40 - i * 7));
  const top_blocked = state.blockedNames.map((name, i) => {
    const count = blockedCounts[i] ?? 0;
    return { name, queries: count + Math.round(count * 0.05), blocked: count };
  });
  const nameCounts = split(queries, NAMES.map(([, w]) => w));
  const top_names = NAMES.map(([name], i) => {
    const count = nameCounts[i] ?? 0;
    return { name, queries: count, blocked: state.blockedNames.includes(name) ? count : 0 };
  });

  const clientQueries = split(queries, CLIENTS.map((c) => c.weight));
  const clientBlocked = split(blocked, CLIENTS.map((c) => c.blockedWeight));
  // A log that keeps no client has no clients to list.
  const top_clients: BlockingStats["top_clients"] =
    state.logClient === "hidden"
      ? []
      : CLIENTS.map((c, i) => {
          const shown = clientOf(state, c, addresses);
          return {
            ...(shown ? { client: shown } : {}),
            ...(shown && state.logClient === "address" && c.name ? { name: c.name } : {}),
            queries: clientQueries[i] ?? 0,
            blocked: clientBlocked[i] ?? 0,
          };
        });

  const recent_blocked: QueryLogLine[] = [];
  for (let n = 0; n < 12; n++) {
    const client = CLIENTS[n % CLIENTS.length]!;
    const shown = clientOf(state, client, addresses);
    recent_blocked.push({
      at: new Date(now - (n + 1) * 41_000).toISOString(),
      ...(shown ? { client: shown } : {}),
      qname: state.blockedNames[n % state.blockedNames.length] ?? "ads.example.test",
      type: n % 5 === 4 ? "AAAA" : "A",
      rcode: 3,
      blocked: n % 6 === 5 ? BLOCKING_IDS.gone : BLOCKING_IDS.ads,
      cached: false,
      transport: n % 3 === 2 ? "tcp" : "udp",
      duration_micros: 90 + n * 13,
    });
  }

  const current = paused(state, now);
  const clients = window === "7d" ? 11 : CLIENTS.length;
  return {
    node: 1,
    window,
    from: hours[0]?.start ?? new Date(now).toISOString(),
    until: new Date(now).toISOString(),
    log_days: state.logDays,
    log_client: state.logClient,
    log_sample: state.logSample,
    queries,
    blocked,
    cached,
    ...(queries > 0 ? { blocked_share: blocked / queries } : {}),
    clients,
    hours,
    lists,
    top_blocked: top_blocked.slice(0, top),
    top_names: top_names.slice(0, top),
    top_clients: top_clients.slice(0, top),
    recent_blocked,
    ...(current ? { paused: current } : {}),
    truncated: state.truncated,
  };
}

/** Pauses the block lists for `minutes` (1 to 1440), or until resumed when absent. */
export function pauseBlocking(state: BlockingState, minutes: unknown, now: number): BlockingPause {
  if (minutes !== undefined && minutes !== null) {
    if (typeof minutes !== "number" || !Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
      throw new DnsLogFailure("sys.invalid_value", 400, "minutes: 1 to 1440", { field: "minutes" });
    }
  }
  const since = new Date(now).toISOString();
  state.paused = typeof minutes === "number" ? { since, until: new Date(now + minutes * 60_000).toISOString() } : { since };
  return state.paused;
}

export function resumeBlocking(state: BlockingState): void {
  state.paused = null;
}

/** What `allowName` decided; the route starts the compile job when `created` or a name was added. */
export interface AllowOutcome {
  allowed: BlockingAllowed;
  /** A name was added: the next version of the list has to be compiled. */
  added: boolean;
}

function covers(allowed: string, name: string): boolean {
  return name === allowed || name.endsWith(`.${allowed}`);
}

/** Adds `name` to the allow list; a name an allowed name covers already changes nothing. */
export function allowName(state: BlockingState, body: { name?: unknown; list?: unknown }, job: () => string): AllowOutcome {
  const raw = typeof body.name === "string" ? body.name.trim().toLowerCase().replace(/\.$/, "") : "";
  if (!/^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(raw) || raw.length > 253) {
    throw new DnsLogFailure("dns.list.invalid", 400, "name: not a DNS name", { field: "name", reason: "not a DNS name" });
  }
  if (body.list !== undefined && body.list !== null && body.list !== BLOCKING_IDS.allowed) {
    throw new DnsLogFailure("dns.list.invalid", 400, "list: not an uploaded allow list", { field: "list", reason: "not an uploaded allow list" });
  }
  const created = !state.allowListExists;
  if (state.allowed.some((a) => covers(a, raw))) {
    return { allowed: { list: BLOCKING_IDS.allowed, list_name: ALLOW_LIST_NAME, created: false, already: true }, added: false };
  }
  state.allowListExists = true;
  state.allowed.push(raw);
  return { allowed: { list: BLOCKING_IDS.allowed, list_name: ALLOW_LIST_NAME, created, already: false, job: job() }, added: true };
}
