// The pure parts of the query log page: the filter form and its check, the query it sends,
// the names of the RCODEs and the kind of a client field.
import type { LogQuery, QueryLogLine } from "./api";

/** The filter form as typed; `from` and `until` are `datetime-local` values (local time). */
export interface LogFilters {
  qname: string;
  client: string;
  rcode: string;
  from: string;
  until: string;
}

export const NO_FILTERS: LogFilters = { qname: "", client: "", rcode: "", from: "", until: "" };

/** Lines per page. */
export const PAGE_SIZE = 50;

/** The RCODEs the filter offers, with their mnemonic (RFC 1035, RFC 2136). */
export const RCODES: readonly (readonly [number, string])[] = [
  [0, "NOERROR"],
  [1, "FORMERR"],
  [2, "SERVFAIL"],
  [3, "NXDOMAIN"],
  [4, "NOTIMP"],
  [5, "REFUSED"],
  [9, "NOTAUTH"],
];

/** The mnemonic of an RCODE, or its number. */
export function rcodeName(rcode: number): string {
  return RCODES.find(([code]) => code === rcode)?.[1] ?? String(rcode);
}

const PSEUDONYM = /^p:[0-9a-f]{8,64}$/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isAddress(text: string): boolean {
  const v4 = IPV4.exec(text);
  if (v4) return v4.slice(1).every((part) => Number(part) <= 255);
  return text.includes(":") && /^[0-9a-f:.]+$/i.test(text);
}

/** What a client field holds. */
export function clientKind(line: Pick<QueryLogLine, "client">): "pseudonym" | "address" | "hidden" {
  if (!line.client) return "hidden";
  return PSEUDONYM.test(line.client) ? "pseudonym" : "address";
}

export type FilterProblem = "client" | "qname" | "until";

/** The fields of the form that cannot be sent as they are. */
export function checkFilters(filters: LogFilters): FilterProblem[] {
  const problems: FilterProblem[] = [];
  const qname = filters.qname.trim();
  if (qname && !/^[a-z0-9_*.-]+\.?$/i.test(qname)) problems.push("qname");
  const client = filters.client.trim();
  if (client && !PSEUDONYM.test(client) && !isAddress(client)) problems.push("client");
  const from = localTime(filters.from);
  const until = localTime(filters.until);
  if (from !== undefined && until !== undefined && until < from) problems.push("until");
  return problems;
}

function localTime(value: string): number | undefined {
  if (!value) return undefined;
  const at = new Date(value).getTime();
  return Number.isNaN(at) ? undefined : at;
}

/** The query of a page; empty fields are left out, times sent in UTC. */
export function toQuery(filters: LogFilters, cursor: string | undefined): LogQuery {
  const query: LogQuery = { limit: PAGE_SIZE };
  if (cursor) query.cursor = cursor;
  const qname = filters.qname.trim();
  if (qname) query.qname = qname;
  const client = filters.client.trim();
  if (client) query.client = client;
  if (filters.rcode !== "") query.rcode = Number(filters.rcode);
  const from = localTime(filters.from);
  if (from !== undefined) query.from = new Date(from).toISOString();
  const until = localTime(filters.until);
  // A datetime-local value names a minute: the window includes all of it.
  if (until !== undefined) query.until = new Date(until + 59_999).toISOString();
  return query;
}

// WP10.4: the validation state and the extended error of a line (recursion plan section 2.11).
/** The validation states a line may carry, in the order the filter offers them. */
export const VALIDATION_STATES = ["secure", "insecure", "bogus", "indeterminate", "unvalidated"] as const;
export type ValidationState = (typeof VALIDATION_STATES)[number];

/** The extended DNS errors of RFC 8914 by code, as the registry names them (protocol words, not translated). */
const EDE_NAMES: Readonly<Record<number, string>> = {
  0: "Other Error",
  1: "Unsupported DNSKEY Algorithm",
  2: "Unsupported DS Digest Type",
  3: "Stale Answer",
  4: "Forged Answer",
  5: "DNSSEC Indeterminate",
  6: "DNSSEC Bogus",
  7: "Signature Expired",
  8: "Signature Not Yet Valid",
  9: "DNSKEY Missing",
  10: "RRSIGs Missing",
  11: "No Zone Key Bit Set",
  12: "NSEC Missing",
  13: "Cached Error",
  14: "Not Ready",
  15: "Blocked",
  16: "Censored",
  17: "Filtered",
  18: "Prohibited",
  19: "Stale NXDOMAIN Answer",
  20: "Not Authoritative",
  21: "Not Supported",
  22: "No Reachable Authority",
  23: "Network Error",
  24: "Invalid Data",
  25: "Signature Expired before Valid",
  26: "Too Early",
  27: "Unsupported NSEC3 Iterations Value",
};

/** The registry name of an extended error, or undefined for a code it does not name. */
export function edeName(code: number): string | undefined {
  return EDE_NAMES[code];
}

/** The lines of a page whose validation state is `state`; every line without a state. */
export function byValidation<T extends { validation?: string | null }>(lines: readonly T[], state: ValidationState | ""): T[] {
  return state === "" ? [...lines] : lines.filter((line) => line.validation === state);
}
// WP10.4: end.

/** Whether any filter is set. */
export function filtered(filters: LogFilters): boolean {
  return Object.values(filters).some((value) => value.trim() !== "");
}
