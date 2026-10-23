// A fake of the infrastructure cache routes of a DNS node (WP10.4), answered in the browser with
// `page.route`: `GET /api/v1/nodes/<id>/dns/infra` and `POST /api/v1/nodes/<id>/dns/infra/flush`.
//
// WHY THE ROUTES ARE FAKED: the e2e server is one controller without the `dns` role (see
// support/dns-resolver-mock.ts), so its node has no resolver and no infrastructure cache. The
// fake answers with the service of the mock API (`src/api/mock/dns-recursion-model.ts`, the code
// the msw handlers and the unit tests run). The Rust tests prove the real listing: `tenko-dns`
// `recursion::infra` and `infra` tests (cuts, order, bounds) and `tenko-api`
// `tests/dns_recursion.rs` `node_routes` (the pages with `suffix`, `limit` and `cursor`, the
// flush and its audit). Install it together with `FakeResolver`, which gives the node the role.

import type { Page, Route } from "@playwright/test";
import { flushInfra, listInfra, seedRecursion, type RecursionState } from "../../src/api/mock/dns-recursion-model";

/** A request the UI sent to a faked infrastructure route. */
export interface InfraRequest {
  method: string;
  query: Record<string, string>;
}

const INFRA = /\/api\/v1\/nodes\/\d+\/dns\/infra(\/flush)?(\?|$)/;

export class FakeInfra {
  readonly state: RecursionState = seedRecursion();
  readonly requests: InfraRequest[] = [];
  private revision = 4_000_000;

  /** Installs the fake in `page`; call it before the first navigation. */
  static async install(page: Page): Promise<FakeInfra> {
    const fake = new FakeInfra();
    await page.route(INFRA, (route) => fake.handle(route));
    return fake;
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const query = Object.fromEntries(url.searchParams.entries());
    this.requests.push({ method: request.method(), query });
    if (request.method() === "POST" && url.pathname.endsWith("/flush")) {
      const entries = flushInfra(this.state, query.suffix);
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ entries }) });
    }
    if (request.method() !== "GET") return route.fallback();
    const page = listInfra(this.state, query, ++this.revision);
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(page) });
  }
}
