// A fake of the blocking routes of a DNS node, answered in the browser with `page.route`:
// `GET /api/v1/dns/blocking/stats`, `POST` and `DELETE /api/v1/dns/blocking/pause` and
// `POST /api/v1/dns/blocking/allow`.
//
// WHY THE ROUTES ARE FAKED: the e2e server is one controller without the `dns` role (see
// support/dns-resolver-mock.ts), so its node has no query log to count and answers 409
// `dns.node.not_dns`. The fake answers with the service of the mock API
// (`src/api/mock/dns-blocking-model.ts`, the code the msw handlers and the unit tests run) and
// adds `dns` to the module list so that the DNS area is shown; everything else reaches the real
// server. The Rust tests prove the real figures: `tenko-dns` `querylog::stats` (the counts over a
// log) and `tenko-api` `tests/dns_blocking.rs` (the routes, the pause and the allow list).

import type { Page, Route } from "@playwright/test";
import { randomUUID } from "node:crypto";
import {
  allowName,
  blockingStats,
  pauseBlocking,
  pausedNow,
  resumeBlocking,
  seedBlocking,
  type BlockingState,
} from "../../src/api/mock/dns-blocking-model";
import { DnsLogFailure } from "../../src/api/mock/dns-log-model";

/** A write the UI sent to a faked route (reads are not recorded). */
export interface BlockingRequest {
  method: string;
  path: string;
  body: unknown;
}

const BLOCKING = /\/api\/v1\/dns\/blocking\/(stats|pause|allow)(\?|$)/;
const MODULES = /\/api\/v1\/system\/modules(\?|$)/;

export class FakeBlocking {
  readonly state: BlockingState = seedBlocking();
  /** The writes, in order. */
  readonly sent: BlockingRequest[] = [];
  /** The windows the figures were read for, in order. */
  readonly reads: string[] = [];

  /** Installs the fake in `page`; call it before the first navigation. */
  static async install(page: Page): Promise<FakeBlocking> {
    const fake = new FakeBlocking();
    await page.route(BLOCKING, (route) => fake.handle(route));
    await page.route(MODULES, (route) => withDns(route));
    return fake;
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const what = BLOCKING.exec(url.pathname)?.[1];
    const raw = request.postData();
    const body: Record<string, unknown> = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    const reply = (status: number, content: unknown) =>
      route.fulfill({ status, contentType: status >= 400 ? "application/problem+json" : "application/json", body: JSON.stringify(content) });
    try {
      if (what === "stats" && method === "GET") {
        const window = url.searchParams.get("window") ?? "24h";
        this.reads.push(window);
        return await reply(200, blockingStats(this.state, window === "7d" ? "7d" : "24h", Number(url.searchParams.get("top") ?? 10), true, Date.now()));
      }
      if (what === "pause" && method === "POST") {
        this.sent.push({ method, path: url.pathname, body });
        const paused = pauseBlocking(this.state, body.minutes, Date.now());
        return await reply(200, { node: 1, paused, command_id: randomUUID() });
      }
      if (what === "pause" && method === "DELETE") {
        this.sent.push({ method, path: url.pathname, body: null });
        resumeBlocking(this.state);
        return await reply(200, { node: 1, command_id: randomUUID() });
      }
      if (what === "allow" && method === "POST") {
        this.sent.push({ method, path: url.pathname, body });
        const outcome = allowName(this.state, body, () => randomUUID());
        return await reply(outcome.allowed.already ? 200 : 202, outcome.allowed);
      }
      return await route.fallback();
    } catch (err) {
      if (err instanceof DnsLogFailure) {
        return await reply(err.status, { type: "about:blank", status: err.status, code: err.code, title: "", detail: err.message, params: err.params });
      }
      throw err;
    }
  }

  /** The pause in force now. */
  paused() {
    return pausedNow(this.state, Date.now());
  }
}

/** The module list of the real server with DNS added, so the area is shown. */
async function withDns(route: Route): Promise<void> {
  if (route.request().method() !== "GET") return route.fallback();
  const response = await route.fetch();
  const body = (await response.json()) as { running?: string[]; configured?: string[] };
  for (const key of ["running", "configured"] as const) {
    if (Array.isArray(body[key]) && !body[key].includes("dns")) body[key].push("dns");
  }
  await route.fulfill({ response, json: body });
}
