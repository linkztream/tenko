// The pure part of the live strip of the lease list (WP8.6): the counter of the leases granted
// since the page was opened (its query, its count, its link, the errors that hide it) and the
// choice and order of the utilization bars shown when no scope is chosen.
import type { Query } from "../../api/client";
import { ApiError } from "../../api/problem";
import { compareCidr, parseCidr } from "../../ipam/ip";
import type { Scope } from "../api";

/** The most grants the counter reads: one page of this many events. */
export const NEW_LIMIT = 1000;

/** The most scope bars the strip shows when no scope is chosen. */
export const SCOPE_BARS = 6;

/** The query of `GET /dhcp/history` for the grants from `since` (RFC 3339), of one scope when `scope` is not empty. */
export function newQuery(since: string, scope: string): Query {
  const prefix = scope.trim();
  return { kind: "granted", from: since, scope: prefix === "" ? undefined : prefix, limit: NEW_LIMIT };
}

export interface NewCount {
  /** The grants counted. */
  count: number;
  /** There are more than the page held: the count is "at least". */
  capped: boolean;
}

/** The count of a history page read with `newQuery`: a page with a successor holds only part of the grants. */
export function countOf(page: { items: readonly unknown[]; next_cursor?: string | null | undefined }): NewCount {
  const capped = (page.next_cursor ?? null) !== null || page.items.length > NEW_LIMIT;
  return { count: Math.min(page.items.length, NEW_LIMIT), capped };
}

/** Whether a failed read of the grants means the principal or the server cannot give them at all (the counter is hidden). */
export function hidesCounter(err: unknown): boolean {
  return err instanceof ApiError && [403, 404, 409, 501].includes(err.status);
}

/** The history view of the same grants: `GET /dhcp/history?kind=granted&from=<since>` with the scope when one is chosen. */
export function newHref(since: string, scope: string): string {
  const prefix = scope.trim();
  return `/dhcp/history?kind=granted&from=${encodeURIComponent(since)}${prefix === "" ? "" : `&scope=${encodeURIComponent(prefix)}`}`;
}

/** The scopes by network: IPv4 before IPv6, then the address, then the shorter prefix; a network that does not parse goes last by text. */
export function byNetwork(scopes: readonly Scope[]): Scope[] {
  return scopes
    .map((scope) => ({ scope, cidr: parseCidr(scope.cidr) }))
    .sort((a, b) => {
      if (a.cidr && b.cidr) return compareCidr(a.cidr, b.cidr);
      if (a.cidr || b.cidr) return a.cidr ? -1 : 1;
      return a.scope.cidr.localeCompare(b.scope.cidr);
    })
    .map(({ scope }) => scope);
}

export interface BarPlan {
  /** The scopes with a bar, the fullest first among those read. */
  shown: Scope[];
  /** The scopes without a bar. */
  more: number;
}

/**
 * The bars of the strip: the first `limit` scopes by network, ordered by how full they are as soon
 * as that is known (`read` holds the percent of each scope read so far); a scope not read yet
 * keeps its place by network behind the ones read. Only the scopes shown are read.
 */
export function barPlan(scopes: readonly Scope[], read: Readonly<Record<string, number>>, limit = SCOPE_BARS): BarPlan {
  const head = byNetwork(scopes).slice(0, limit);
  const shown = head
    .map((scope, order) => ({ scope, order, percent: read[scope.prefix] }))
    .sort((a, b) => {
      if (a.percent !== undefined && b.percent !== undefined && a.percent !== b.percent) return b.percent - a.percent;
      if ((a.percent === undefined) !== (b.percent === undefined)) return a.percent === undefined ? 1 : -1;
      return a.order - b.order;
    })
    .map(({ scope }) => scope);
  return { shown, more: Math.max(0, scopes.length - head.length) };
}
