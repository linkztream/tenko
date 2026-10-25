// A fake of the lease routes of the DHCP role with DHCPv4 and DHCPv6 clients, answered in the
// browser with `page.route`: `GET /api/v1/dhcp/leases`, `GET /api/v1/dhcp/leases/<addr>`,
// `GET /api/v1/dhcp/history` and `GET /api/v1/nodes/<id>/dhcp`.
//
// WHY THE ROUTES ARE FAKED: the e2e server is one controller with no DHCPv6 client behind it (the
// DHCP client of support/dhcp-client.ts speaks DHCPv4 only), so its lease table holds no DHCPv6
// lease and its node answers 409 `dhcp.node.not_dhcp`. The fake answers with the lease model of
// the mock API (`src/api/mock/dhcp-leases-model.ts`, the code the msw handlers and the unit tests
// run): twelve DHCPv4 leases, four DHCPv6 leases and a delegated prefix (WP9.2) with the address
// lease of its client, the peer that joins a client's two leases by MAC address and the history of
// both families. The Rust tests prove the real routes: the lease list, the family, kind
// and DUID filters, the prefix-aware address filter, the peer and the release of a DHCPv6 lease in
// `crates/tenko-api/tests/dhcp_leases.rs`, and the merged history of both families in
// `crates/tenko-dhcp/tests/history_both.rs`. Writes (the release) fall through to the real server.

import type { Page, Route } from "@playwright/test";
import {
  findLease,
  listEvents,
  listLeases,
  nodeStatusOf,
  pageOf,
  QueryError,
  seedLeases,
  withPeer,
  type LeaseState,
} from "../../src/api/mock/dhcp-leases-model";

/** A request the UI sent to a faked route. */
export interface LeaseRequest {
  method: string;
  path: string;
  query: Record<string, string>;
}

/** The VRFs of the two scopes of the seed; any identifiers will do, nothing in the page reads them. */
const VRFS = { lan: "0190d1c2-0000-7000-8000-00000000f001", lanV6: "0190d1c2-0000-7000-8000-00000000f001" };

const LEASES = /\/api\/v1\/dhcp\/(leases(\/[^/?]+)?|history)(\?|$)/;
const NODE = /\/api\/v1\/nodes\/\d+\/dhcp(\?|$)/;

export class FakeLeases {
  readonly state: LeaseState = seedLeases(VRFS);
  /** Every request the fake answered, in order. */
  readonly requests: LeaseRequest[] = [];
  private revision = 4_000_000;

  /** Installs the fake in `page`; call it before the first navigation. */
  static async install(page: Page): Promise<FakeLeases> {
    const fake = new FakeLeases();
    await page.route(LEASES, (route) => fake.handle(route));
    await page.route(NODE, (route) => fake.handle(route));
    return fake;
  }

  /** The requests of one path, such as `/api/v1/dhcp/leases`. */
  to(path: string): LeaseRequest[] {
    return this.requests.filter((r) => r.path === path);
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    if (request.method() !== "GET") return route.fallback();
    const url = new URL(request.url());
    this.requests.push({ method: request.method(), path: url.pathname, query: Object.fromEntries(url.searchParams.entries()) });
    const revision = ++this.revision;
    try {
      if (/\/nodes\/\d+\/dhcp$/.test(url.pathname)) return json(route, 200, nodeStatusOf(this.state, revision));
      if (url.pathname.endsWith("/dhcp/history")) return json(route, 200, pageOf(listEvents(this.state, url.searchParams), url.searchParams, revision));
      if (url.pathname.endsWith("/dhcp/leases")) return json(route, 200, pageOf(listLeases(this.state, url.searchParams), url.searchParams, revision));
      const addr = decodeURIComponent(url.pathname.split("/").pop() ?? "");
      const found = findLease(this.state, addr, url.searchParams.get("vrf"));
      if (!found) return problem(route, 404, "dhcp.lease.not_found", `no lease holds ${addr}`);
      return json(route, 200, withPeer(this.state, found));
    } catch (err) {
      if (err instanceof QueryError) return problem(route, 400, "sys.invalid_query", `${err.param}: ${err.value}`);
      throw err;
    }
  }
}

function json(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function problem(route: Route, status: number, code: string, detail: string): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/problem+json",
    body: JSON.stringify({ type: "about:blank", status, code, title: status === 404 ? "Not Found" : "Bad Request", detail, params: {} }),
  });
}
