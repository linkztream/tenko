// The query log of the one DNS node of the mock (WP5.4), as the server keeps it: lines newest
// first, a cursor, the filters of `GET /nodes/{id}/dns/log` (the name and the names under it,
// a client by pseudonym or address, the RCODE, a time window), the kill switch, and the client
// field per the settings (a pseudonym, the address, or nothing). Addresses reach only a caller
// that may update the node. Pure code without msw, shared with the browser fake of the
// end-to-end test (e2e/dns-log.spec.ts).
import type { components } from "../generated/schema";

export type QueryLogLine = components["schemas"]["QueryLogLine"];
export type QueryLogStatus = components["schemas"]["QueryLogStatus"];

/** One logged query with both forms of its client, as the node holds it. */
export interface LogEntry {
  at: string;
  address: string;
  pseudonym: string;
  transport: QueryLogLine["transport"];
  qname: string;
  type: string;
  rcode: number;
  cached: boolean;
  duration_micros: number;
}

export interface DnsLogState {
  /** `off`: the node logs nothing (`[dns.log]` or the profile). */
  mode: "on" | "stopped" | "off";
  /** What the log keeps of the client. */
  client: "pseudonym" | "address" | "hidden";
  /** Oldest first. */
  entries: LogEntry[];
  written: number;
  dropped: number;
}

export class DnsLogFailure extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
    readonly params: Record<string, string> = {},
  ) {
    super(message);
  }
}

const NAMES = ["www.example.test", "mail.example.test", "printer.lab.example.test", "missing.example.test", "nas.example.test", "time.example.org"];
const TYPES = ["A", "AAAA", "MX", "A", "AAAA", "A"];
const RCODES = [0, 0, 0, 3, 0, 2];
const CLIENTS: Array<[string, string]> = [
  ["192.0.2.10", "p:3f2a9c0d81b7e645"],
  ["192.0.2.11", "p:9b1e44c2a07d3f18"],
  ["2001:db8::20", "p:c45d0e9f7a12b366"],
];
const TRANSPORTS: Array<QueryLogLine["transport"]> = ["udp", "udp", "tcp", "dot", "doh"];

/** 60 queries, one a second, the newest at 2026-10-17T12:00:59Z. */
export function seedDnsLog(): DnsLogState {
  const start = Date.parse("2026-10-17T12:00:00Z");
  const entries: LogEntry[] = [];
  for (let n = 0; n < 60; n++) {
    const [address, pseudonym] = CLIENTS[n % CLIENTS.length] ?? CLIENTS[0]!;
    entries.push({
      at: new Date(start + n * 1000).toISOString(),
      address,
      pseudonym,
      transport: TRANSPORTS[n % TRANSPORTS.length] ?? "udp",
      qname: NAMES[n % NAMES.length] ?? "www.example.test",
      type: TYPES[n % TYPES.length] ?? "A",
      rcode: RCODES[n % RCODES.length] ?? 0,
      cached: n % 4 === 1,
      duration_micros: 40 + ((n * 37) % 900),
    });
  }
  return { mode: "on", client: "pseudonym", entries, written: entries.length, dropped: 0 };
}

/** The `query_log` member of `GET /nodes/{id}/dns`; absent while the log is off. */
export function logStatus(state: DnsLogState): QueryLogStatus | undefined {
  if (state.mode === "off") return undefined;
  return {
    state: state.mode === "stopped" ? "stopped" : "on",
    format: "jsonl",
    client: state.client,
    sample: 1,
    days: 7,
    size_mb: 256,
    written: state.written,
    dropped: state.dropped,
    write_errors: 0,
  };
}

export interface LogQuery {
  cursor?: string | null;
  limit?: string | null;
  qname?: string | null;
  client?: string | null;
  rcode?: string | null;
  from?: string | null;
  until?: string | null;
}

const PSEUDONYM = /^p:[0-9a-f]{8,64}$/i;
const ADDRESS = /^[0-9a-f:.]+$/i;

function invalid(field: string, message: string): DnsLogFailure {
  return new DnsLogFailure("sys.invalid_value", 400, message, { field });
}

function notDns(): DnsLogFailure {
  return new DnsLogFailure("dns.node.not_dns", 409, "the query log is off on this node", { node: "1" });
}

function under(name: string, suffix: string): boolean {
  const s = suffix.trim().replace(/\.$/, "").toLowerCase();
  const n = name.toLowerCase();
  return s === "" || n === s || n.endsWith(`.${s}`);
}

function time(text: string, field: string): number {
  const at = Date.parse(text);
  if (Number.isNaN(at)) throw invalid(field, `${field} is not a time`);
  return at;
}

/**
 * A page of the log, newest first, as the API answers it. `addresses`: the caller may update
 * the node, so a logged address is returned; any other caller gets pseudonyms only.
 */
export function readLog(state: DnsLogState, query: LogQuery, addresses: boolean, revision: number): { items: QueryLogLine[]; next_cursor: string | null; revision: number } {
  const limit = query.limit ? Number(query.limit) : 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw invalid("limit", "limit must be between 1 and 1000");
  const rcode = query.rcode ? Number(query.rcode) : undefined;
  if (rcode !== undefined && (!Number.isInteger(rcode) || rcode < 0 || rcode > 4095)) throw invalid("rcode", "rcode must be between 0 and 4095");
  const client = query.client?.trim() || undefined;
  if (client && !PSEUDONYM.test(client) && !ADDRESS.test(client)) throw invalid("client", `client ${client} is neither an address nor a pseudonym`);
  const byAddress = client !== undefined && !PSEUDONYM.test(client);
  if (byAddress && !addresses) throw new DnsLogFailure("auth.forbidden", 403, "a filter by address needs the right to update the node");
  const from = query.from ? time(query.from, "from") : undefined;
  const until = query.until ? time(query.until, "until") : undefined;
  if (from !== undefined && until !== undefined && until < from) throw invalid("until", "until is before from");
  if (state.mode === "off") throw notDns();
  let start = state.entries.length;
  if (query.cursor) {
    const match = /^m:(\d+)$/.exec(query.cursor);
    if (!match) throw new DnsLogFailure("dns.node.not_dns", 409, "dns.log.read: the cursor is not valid");
    start = Math.min(Number(match[1]), state.entries.length);
  }
  const items: QueryLogLine[] = [];
  let index = start - 1;
  for (; index >= 0 && items.length < limit; index--) {
    const entry = state.entries[index]!;
    const at = Date.parse(entry.at);
    if (query.qname && !under(entry.qname, query.qname)) continue;
    if (rcode !== undefined && entry.rcode !== rcode) continue;
    if (from !== undefined && at < from) continue;
    if (until !== undefined && at > until) continue;
    if (client && (byAddress ? entry.address !== client : entry.pseudonym.toLowerCase() !== client.toLowerCase())) continue;
    items.push(lineOf(state, entry, addresses));
  }
  const more = items.length === limit && index >= 0;
  return { items, next_cursor: more ? `m:${index + 1}` : null, revision };
}

function lineOf(state: DnsLogState, entry: LogEntry, addresses: boolean): QueryLogLine {
  const line: QueryLogLine = {
    at: entry.at,
    transport: entry.transport,
    qname: entry.qname,
    type: entry.type,
    rcode: entry.rcode,
    cached: entry.cached,
    duration_micros: entry.duration_micros,
  };
  if (state.client === "pseudonym") line.client = entry.pseudonym;
  else if (state.client === "address" && addresses) line.client = entry.address;
  return line;
}

/** The kill switch: `dns.log.stop` or `dns.log.start`. */
export function switchLog(state: DnsLogState, stop: boolean): void {
  if (state.mode === "off") throw notDns();
  state.mode = stop ? "stopped" : "on";
}
