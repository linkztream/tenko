// A fake of the cache routes of a DNS node, answered in the browser with `page.route`:
// `GET /api/v1/nodes/<id>/dns/cache` and `POST /api/v1/nodes/<id>/dns/cache/flush`.
//
// WHY THE ROUTES ARE FAKED: the e2e server is one controller without the `dns` role (see
// support/dns-resolver-mock.ts), so its node answers 409 `dns.node.not_dns` and its cache is
// empty. The fake answers with the service of the mock API (`src/api/mock/dns-cache-model.ts`,
// the code the msw handlers and the unit tests run). The Rust tests prove the real listing:
// `tenko-dns` `cache::list::tests` (order, cursor, filters, stale state), `status::tests`
// (the node command) and `tenko-api` `tests/dns_cache.rs` (the route and its audit).
// Install it together with `FakeResolver`, which gives the node the `dns` role.

import type { Page, Route } from "@playwright/test";
import { flushCache, listCache, seedDnsCache, type DnsCacheState } from "../../src/api/mock/dns-cache-model";

/** A request the UI sent to a faked cache route. */
export interface CacheRequest {
  method: string;
  path: string;
  query: Record<string, string>;
}

const CACHE = /\/api\/v1\/nodes\/\d+\/dns\/cache(\/flush)?(\?|$)/;

export class FakeCache {
  readonly state: DnsCacheState = seedDnsCache();
  /** Every request, reads included: each read is one the server would audit. */
  readonly requests: CacheRequest[] = [];
  private revision = 3_000_000;

  /** Installs the fake in `page`; call it before the first navigation. */
  static async install(page: Page): Promise<FakeCache> {
    const fake = new FakeCache();
    await page.route(CACHE, (route) => fake.handle(route));
    return fake;
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const query = Object.fromEntries(url.searchParams.entries());
    this.requests.push({ method: request.method(), path: url.pathname, query });
    if (request.method() === "POST" && url.pathname.endsWith("/flush")) {
      flushCache(this.state, query.suffix);
      return route.fulfill({ status: 202, contentType: "application/json", body: JSON.stringify({ command_id: crypto.randomUUID() }) });
    }
    if (request.method() !== "GET") return route.fallback();
    const page = listCache(this.state, query, ++this.revision);
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(page) });
  }
}
