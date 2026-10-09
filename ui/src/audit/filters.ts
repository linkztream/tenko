// The filters of the audit log. They live in the URL query under the names of the API
// parameters (`from`, `to`, `principal`, `action`, `object`, `outcome`, `order`), so a
// filtered view is a link. This module reads them, checks each value the way the server
// does (so a bad value is explained next to its field instead of ending as a 400) and
// builds the query of GET /api/v1/audit.
//
// Formats:
// - `from` and `to` are RFC 3339 times in UTC in the URL ("2026-10-09T10:00:00Z"); the
//   inputs show and take local time (`datetime-local`). `from` is inclusive, `to` exclusive.
// - `principal` is the subject of the API: `user:<uuid>`, `token:<uuid>`, `node:<number>` or
//   `system:<component>`. The field also takes the name of a user, which the view turns
//   into `user:<uuid>` when it commits the value.
// - `action` is a full action ("ipam.prefix.create") or a group that ends with a dot ("ipam.").
// - `object` is a kind ("prefix") or one object ("prefix:<uuid>").
import type { Query } from "../api/client";
import { isObjectKind, SYSTEM_COMPONENTS } from "./model";

/** The messages that explain a filter value the UI cannot use; none of them takes arguments. */
export type FilterProblem =
  | "audit.filter.principal_invalid"
  | "audit.filter.action_invalid"
  | "audit.filter.object_invalid"
  | "audit.filter.time_invalid"
  | "audit.filter.value_invalid";

export const FILTER_NAMES = ["from", "to", "principal", "action", "object", "outcome", "order"] as const;
export type FilterName = (typeof FILTER_NAMES)[number];

/** The raw values of the URL query; absent when the filter is off. */
export type FilterValues = Partial<Record<FilterName, string>>;

export const OUTCOMES = ["success", "denied", "failed"] as const;
export type OutcomeFilter = (typeof OUTCOMES)[number];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SEGMENT = /^[a-z0-9_-]+$/;
/** What the server accepts as a time: RFC 3339 with a zone. */
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

type Search = Readonly<Record<string, string | string[] | undefined>>;

/** The filters in a router search object; the first value of a repeated parameter wins. */
export function readFilters(search: Search): FilterValues {
  const out: FilterValues = {};
  for (const name of FILTER_NAMES) {
    const raw = search[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== undefined && value !== "") out[name] = value;
  }
  return out;
}

/** The text a person typed, in the form the API compares: trimmed and in lower case. */
export function normalize(text: string): string {
  return text.trim().toLowerCase();
}

export function checkAction(raw: string): FilterProblem | undefined {
  const text = normalize(raw);
  // A prefix matches when some action starts with it: the prefix plus one more character
  // must be an action.
  const probe = text.endsWith(".") ? `${text}x` : text;
  const segments = probe.split(".");
  const ok = probe.length <= 128 && segments.length >= 2 && segments.every((s) => SEGMENT.test(s));
  return ok ? undefined : "audit.filter.action_invalid";
}

export function checkObject(raw: string): FilterProblem | undefined {
  const text = normalize(raw);
  const colon = text.indexOf(":");
  const kind = colon < 0 ? text : text.slice(0, colon);
  if (!isObjectKind(kind)) return "audit.filter.object_invalid";
  if (colon >= 0 && !UUID.test(text.slice(colon + 1))) return "audit.filter.object_invalid";
  return undefined;
}

/** Whether `text` is a principal subject of the API. */
export function isSubject(raw: string): boolean {
  const text = normalize(raw);
  const colon = text.indexOf(":");
  if (colon < 0) return false;
  const id = text.slice(colon + 1);
  switch (text.slice(0, colon)) {
    case "user":
    case "token":
      return UUID.test(id);
    case "node":
      return /^\d+$/.test(id);
    case "system":
      return (SYSTEM_COMPONENTS as readonly string[]).includes(id);
    default:
      return false;
  }
}

export function checkPrincipal(raw: string): FilterProblem | undefined {
  return isSubject(raw) ? undefined : "audit.filter.principal_invalid";
}

export function checkTime(raw: string): FilterProblem | undefined {
  return RFC3339.test(raw) && !Number.isNaN(Date.parse(raw)) ? undefined : "audit.filter.time_invalid";
}

export function checkOutcome(raw: string): FilterProblem | undefined {
  return (OUTCOMES as readonly string[]).includes(normalize(raw)) ? undefined : "audit.filter.value_invalid";
}

/** The problem with a filter value, or undefined when it is fine. */
export function filterProblem(name: FilterName, value: string): FilterProblem | undefined {
  switch (name) {
    case "action":
      return checkAction(value);
    case "object":
      return checkObject(value);
    case "principal":
      return checkPrincipal(value);
    case "from":
    case "to":
      return checkTime(value);
    case "outcome":
      return checkOutcome(value);
    case "order":
      return normalize(value) === "asc" || normalize(value) === "desc" ? undefined : "audit.filter.value_invalid";
  }
}

export interface FilterState {
  /** The problem of each filter whose URL value cannot be used. */
  problems: Partial<Record<FilterName, FilterProblem>>;
  /** The query of GET /api/v1/audit: only the filters whose value is fine. */
  query: Query;
  /** The order of the list. */
  order: "asc" | "desc";
  /** Whether any filter other than the order narrows the list. */
  filtered: boolean;
  /** `to` is not after `from`: nothing can match. */
  emptyRange: boolean;
}

/** Checks the URL values and builds the query; bad values are reported, never sent. */
export function filterState(values: FilterValues): FilterState {
  const problems: FilterState["problems"] = {};
  const query: Record<string, string> = {};
  for (const name of FILTER_NAMES) {
    const value = values[name];
    if (value === undefined) continue;
    const problem = filterProblem(name, value);
    if (problem) {
      problems[name] = problem;
      continue;
    }
    const text = name === "from" || name === "to" ? value : normalize(value);
    if (name === "order") {
      if (text === "asc") query.order = "asc";
      continue;
    }
    query[name] = text;
  }
  const filtered = Object.keys(query).some((k) => k !== "order");
  const from = query.from === undefined ? NaN : Date.parse(query.from);
  const to = query.to === undefined ? NaN : Date.parse(query.to);
  return {
    problems,
    query,
    order: query.order === "asc" ? "asc" : "desc",
    filtered,
    emptyRange: !Number.isNaN(from) && !Number.isNaN(to) && to <= from,
  };
}

// ---------------------------------------------------------------------------------
// Local time in the inputs, UTC in the URL

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}

/** The value of a `datetime-local` input ("2026-10-09T12:00", local time) as RFC 3339 UTC. */
export function toRfc3339(local: string): string | undefined {
  if (local === "") return undefined;
  const at = new Date(local);
  if (Number.isNaN(at.getTime())) return undefined;
  return at.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** An RFC 3339 time as the value of a `datetime-local` input; empty when it is not a time. */
export function toLocalInput(rfc: string | undefined): string {
  if (rfc === undefined) return "";
  const at = new Date(rfc);
  if (Number.isNaN(at.getTime())) return "";
  return `${pad(at.getFullYear(), 4)}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}
