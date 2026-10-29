// The pure part of the live strip of the lease list (WP8.6): the counter of the leases granted
// since the page was opened (its query, its count, its link, the errors that hide it) and the
// choice and order of the utilization bars shown when no scope is chosen; and the counts of the
// status strip of the role, with both address families side by side (WP9.4).
import type { Query } from "../../api/client";
import { ApiError } from "../../api/problem";
import { compareCidr, parseCidr } from "../../ipam/ip";
import type { Scope } from "../api";
import type { BindingState, NodeStatus } from "./model";

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

/**
 * The count of a history page read with `newQuery`: a page with a successor holds only part of the
 * grants. A read that answered no page (an empty body) is no count: undefined.
 */
export function countOf(page: { items: readonly unknown[]; next_cursor?: string | null | undefined } | null | undefined): NewCount | undefined {
  if (!page || !Array.isArray(page.items)) return undefined;
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

/** The leases of one state in each address family. */
export interface LeaseTotals {
  state: BindingState;
  v4: number;
  v6: number;
}

/** Whether the node serves DHCPv6 at all: a scope, a listener or a lease of that family. An older server says nothing of it. */
export function hasV6(node: Pick<NodeStatus, "scopes6" | "listeners6" | "leases6">): boolean {
  return (node.scopes6 ?? 0) > 0 || (node.listeners6?.length ?? 0) > 0 || (node.leases6?.length ?? 0) > 0;
}

/**
 * The leases by state with both families side by side: the DHCPv4 states in the order the server
 * lists them, then the states only DHCPv6 has. The active state is always there when the node
 * serves DHCPv6, with 0 where a family has none, so the strip can say "12 DHCPv4 and 0 DHCPv6".
 */
export function leaseTotals(node: Pick<NodeStatus, "leases" | "leases6" | "scopes6" | "listeners6">): LeaseTotals[] {
  const totals = new Map<BindingState, LeaseTotals>();
  const at = (state: BindingState): LeaseTotals => {
    let found = totals.get(state);
    if (!found) {
      found = { state, v4: 0, v6: 0 };
      totals.set(state, found);
    }
    return found;
  };
  for (const entry of node.leases) at(entry.state).v4 += entry.count;
  for (const entry of node.leases6 ?? []) at(entry.state).v6 += entry.count;
  if (hasV6(node)) at("active");
  return [...totals.values()];
}
