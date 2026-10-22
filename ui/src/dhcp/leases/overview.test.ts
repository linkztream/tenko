// The rules of the live strip: the query, the count and the link of the counter of new leases, the
// errors that hide it, and which scope bars are shown in which order.
import { describe, expect, it } from "vitest";
import { ApiError } from "../../api/problem";
import type { Scope } from "../api";
import { barPlan, byNetwork, countOf, hidesCounter, newHref, newQuery, NEW_LIMIT, SCOPE_BARS } from "./overview";

const SINCE = "2026-03-01T10:15:30.250Z";

function scope(cidr: string): Scope {
  return { prefix: `id-${cidr}`, cidr, pools: 1, leases: 0, revision: 1 } as unknown as Scope;
}

function problem(status: number): ApiError {
  return new ApiError({ status, code: "x.y", title: "t", detail: "d" });
}

describe("the counter of new leases", () => {
  it("asks for the grants from the start with one page of a thousand", () => {
    expect(newQuery(SINCE, "")).toEqual({ kind: "granted", from: SINCE, scope: undefined, limit: 1000 });
    expect(newQuery(SINCE, " abc ")).toEqual({ kind: "granted", from: SINCE, scope: "abc", limit: NEW_LIMIT });
  });

  it("counts the events of the page and says when the page held only part of them", () => {
    const items = (n: number) => Array.from({ length: n }, (_, i) => i);
    expect(countOf({ items: [], next_cursor: null })).toEqual({ count: 0, capped: false });
    expect(countOf({ items: items(999) })).toEqual({ count: 999, capped: false });
    // Exactly a thousand with nothing after them is a count, not a cap.
    expect(countOf({ items: items(1000), next_cursor: null })).toEqual({ count: 1000, capped: false });
    expect(countOf({ items: items(1000), next_cursor: "next" })).toEqual({ count: 1000, capped: true });
    // A server that cuts the page shorter says how many it counted.
    expect(countOf({ items: items(500), next_cursor: "next" })).toEqual({ count: 500, capped: true });
    expect(countOf({ items: items(1200), next_cursor: null })).toEqual({ count: 1000, capped: true });
  });

  it("links to the history of the same grants, with the scope when one is chosen", () => {
    const href = newHref(SINCE, "");
    expect(href.startsWith("/dhcp/history?kind=granted&from=")).toBe(true);
    expect(href).not.toContain("scope");
    const url = new URL(newHref(SINCE, "abc"), "http://localhost");
    expect(url.pathname).toBe("/dhcp/history");
    expect(url.searchParams.get("kind")).toBe("granted");
    expect(url.searchParams.get("from")).toBe(SINCE);
    expect(url.searchParams.get("scope")).toBe("abc");
  });

  it("is hidden for a history the principal may not read or a server does not have, and for nothing else", () => {
    for (const status of [403, 404, 409, 501]) expect(hidesCounter(problem(status))).toBe(true);
    for (const status of [400, 500, 503]) expect(hidesCounter(problem(status))).toBe(false);
    expect(hidesCounter(new Error("network"))).toBe(false);
  });
});

describe("the scope bars", () => {
  it("orders the networks IPv4 before IPv6, by address, and the ones that do not parse last", () => {
    const list = [scope("2001:db8::/32"), scope("192.0.2.64/26"), scope("nonsense"), scope("192.0.2.0/24"), scope("198.51.100.0/24")];
    expect(byNetwork(list).map((s) => s.cidr)).toEqual(["192.0.2.0/24", "192.0.2.64/26", "198.51.100.0/24", "2001:db8::/32", "nonsense"]);
  });

  const many = Array.from({ length: 9 }, (_, i) => scope(`192.0.2.${i * 16}/28`));
  const id = (i: number) => `id-192.0.2.${i * 16}/28`;

  it("shows the first six by network and counts the rest", () => {
    const plan = barPlan(many, {});
    expect(SCOPE_BARS).toBe(6);
    expect(plan.shown.map((s) => s.prefix)).toEqual([0, 1, 2, 3, 4, 5].map(id));
    expect(plan.more).toBe(3);
    expect(barPlan(many.slice(0, 2), {})).toEqual({ shown: many.slice(0, 2), more: 0 });
    expect(barPlan([], {})).toEqual({ shown: [], more: 0 });
  });

  it("puts the fullest first once read, and the ones not read yet behind them in network order", () => {
    const read = { [id(1)]: 40, [id(3)]: 90, [id(4)]: 40 };
    expect(barPlan(many, read).shown.map((s) => s.prefix)).toEqual([3, 1, 4, 0, 2, 5].map(id));
    // The scopes beyond the six are never part of the order, however full they are.
    expect(barPlan(many, { [id(8)]: 100 }).shown.map((s) => s.prefix)).toEqual([0, 1, 2, 3, 4, 5].map(id));
  });
});
