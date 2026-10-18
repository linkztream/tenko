// WP5.4: the query log page of a DNS node. Read the newest queries, filter them by RCODE and by
// name, page to older queries by cursor and back, stop and start the log (the kill switch), the
// empty state of a log that is off with its link to the settings, Swedish, and what the page
// shows against the real server.
//
// THE FIRST SCENARIOS FAKE THE NODE'S DNS ROUTES: the e2e server is one controller without the
// `dns` role (support/server.ts writes `roles = "controller"`), so it has no query log to read.
// The fake answers `/api/v1/nodes/<id>/dns` and its `log` routes in the browser with the log of
// the mock API (src/api/mock/dns-log-model.ts, the same code the msw handlers and the unit tests
// run) and lets everything else reach the real server. The real path is proven in Rust:
// crates/tenko-api/tests/dns_log.rs (the route over a real local role: pages, filters, cursor,
// withheld addresses, the kill switch, the audit records) and crates/tenko/tests/acceptance_dns.rs
// (`tenko serve` with the role, queries over UDP, the log read and the kill switch).

import type { Page, Route } from "@playwright/test";
import { DnsLogFailure, logStatus, readLog, seedDnsLog, switchLog, type DnsLogState } from "../src/api/mock/dns-log-model";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

const NODE_ROUTES = /\/api\/v1\/nodes\/\d+\/dns(\/[a-z/]*)?(\?|$)/;
const MODULES = /\/api\/v1\/system\/modules(\?|$)/;
const STATUS = /\/api\/v1\/system\/status(\?|$)/;

/** A request the page sent to the faked routes. */
interface Sent {
  method: string;
  path: string;
  query: URLSearchParams;
}

class FakeLog {
  state: DnsLogState = seedDnsLog();
  readonly sent: Sent[] = [];

  static async install(page: Page): Promise<FakeLog> {
    const fake = new FakeLog();
    await page.route(NODE_ROUTES, (route) => fake.answer(route));
    await page.route(MODULES, (route) => withDns(route));
    // The node of a server that is not part of a cluster yet has no id; the page needs one.
    await page.route(STATUS, async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as { node?: { id?: number | null; roles?: string[] } };
      if (body.node && (body.node.id === null || body.node.id === undefined)) body.node.id = 1;
      await route.fulfill({ response, json: body });
    });
    return fake;
  }

  reads(): URLSearchParams[] {
    return this.sent.filter((s) => s.method === "GET" && s.path.endsWith("/dns/log")).map((s) => s.query);
  }

  private async answer(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    this.sent.push({ method, path: url.pathname, query: url.searchParams });
    const reply = (status: number, body: unknown) =>
      route.fulfill({ status, contentType: status >= 400 ? "application/problem+json" : "application/json", body: JSON.stringify(body) });
    try {
      if (method === "GET" && url.pathname.endsWith("/dns")) {
        const log = logStatus(this.state);
        return await reply(200, {
          node: 1,
          serving: true,
          revision: 1,
          lag: 0,
          zones: 0,
          rrsets: 0,
          listeners: [],
          cache_entries: 0,
          ...(log ? { query_log: log } : {}),
        });
      }
      if (method === "GET" && url.pathname.endsWith("/dns/log")) {
        const q = (name: string) => url.searchParams.get(name);
        const page = readLog(
          this.state,
          { cursor: q("cursor"), limit: q("limit"), qname: q("qname"), client: q("client"), rcode: q("rcode"), from: q("from"), until: q("until") },
          true,
          1,
        );
        return await reply(200, page);
      }
      if (method === "POST" && (url.pathname.endsWith("/dns/log/stop") || url.pathname.endsWith("/dns/log/start"))) {
        switchLog(this.state, url.pathname.endsWith("/stop"));
        return await reply(202, { command_id: "0192f1a0-0000-7000-8000-000000000001" });
      }
      return await route.fallback();
    } catch (err) {
      if (err instanceof DnsLogFailure) {
        return await reply(err.status, { type: "about:blank", status: err.status, code: err.code, title: "", detail: err.message, params: err.params });
      }
      throw err;
    }
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

const rows = (page: Page) => page.getByTestId("dns-log-table").getByTestId("dns-log-row");

test("reads the newest queries, filters them and pages by cursor", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeLog.install(page);
  await page.goto("/dns/log");
  await expect(page.getByTestId("page-dns-log")).toBeVisible();
  await expect(rows(page)).toHaveCount(50);
  await expect(rows(page).first()).toHaveAttribute("data-key", "time.example.org");
  await expect(rows(page).first().getByTestId("dns-log-client")).toHaveAttribute("data-kind", "pseudonym");
  await expect(page.getByTestId("dns-log-figures")).toHaveAttribute("data-written", "60");
  await expect(page.getByTestId("dns-nav").locator('[data-key="log"]')).toHaveAttribute("aria-current", "page");

  // Filter: the RCODE and the name under a domain.
  const filters = page.getByTestId("dns-log-filters");
  await filters.getByTestId("field-rcode").selectOption("3");
  await filters.getByTestId("field-qname").fill("example.test");
  await filters.getByTestId("form-submit").click();
  await expect(rows(page)).toHaveCount(10);
  for (const row of await rows(page).all()) {
    await expect(row).toHaveAttribute("data-rcode", "3");
    await expect(row).toHaveAttribute("data-key", "missing.example.test");
  }
  const filtered = fake.reads().at(-1);
  expect(filtered?.get("rcode")).toBe("3");
  expect(filtered?.get("qname")).toBe("example.test");
  expect(filtered?.has("cursor")).toBe(false);

  // A filter that matches nothing, then the filters cleared.
  await filters.getByTestId("field-qname").fill("nowhere.example.test");
  await filters.getByTestId("form-submit").click();
  await expect(page.getByTestId("dns-log-empty")).toHaveAttribute("data-filtered", "true");
  await page.getByTestId("dns-log-reset").click();
  await expect(rows(page)).toHaveCount(50);

  // Page: older by the cursor of the page, then back to the newest.
  await expect(page.getByTestId("dns-log-newer")).toBeDisabled();
  await page.getByTestId("dns-log-older").click();
  await expect(rows(page)).toHaveCount(10);
  await expect(page.getByTestId("dns-log-paging")).toHaveAttribute("data-page", "2");
  expect(fake.reads().at(-1)?.get("cursor")).toBe("m:10");
  await expect(page.getByTestId("dns-log-older")).toBeDisabled();
  await page.getByTestId("dns-log-newer").click();
  await expect(rows(page)).toHaveCount(50);
  await expect(rows(page).first()).toHaveAttribute("data-key", "time.example.org");
});

test("stops and starts the log, and shows where a log that is off is set", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeLog.install(page);
  await page.goto("/dns/log");
  await expect(rows(page)).toHaveCount(50);
  await page.getByTestId("dns-log-stop").click();
  await expect(page.getByTestId("dns-log-stopped")).toBeVisible();
  await expect(page.getByTestId("dns-log-figures")).toHaveAttribute("data-state", "stopped");
  expect(fake.state.mode).toBe("stopped");
  await page.getByTestId("dns-log-start").click();
  await expect(page.getByTestId("dns-log-stopped")).toHaveCount(0);
  expect(fake.sent.filter((s) => s.method === "POST").map((s) => s.path.split("/").pop())).toEqual(["stop", "start"]);

  fake.state.mode = "off";
  await page.reload();
  const off = page.getByTestId("dns-log-off");
  await expect(off).toBeVisible();
  await expect(page.getByTestId("dns-log-filters")).toHaveCount(0);
  await expect(page.getByTestId("dns-log-stop")).toHaveCount(0);
  await off.getByTestId("dns-log-settings-link").click();
  await expect(page).toHaveURL(/\/settings\/security$/);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the log page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeLog.install(page);
    await page.goto("/dns/log");
    await expect(rows(page)).toHaveCount(50);
    await expectRendered(page, page.getByTestId("page-dns-log"), "sv", testInfo, "dns-log");
    await expect(page.getByTestId("dns-log-filters").getByTestId("form-submit")).toHaveText("Visa");
    await expect(rows(page).first().locator('[data-col="transport"]')).toHaveText("DNS över HTTPS");
  });
});

test("says so against the real server, whose one node does not run the dns role", async ({ page, signedIn }) => {
  void signedIn;
  // No fake of the node routes: the real server answers. With the DNS module on, the node
  // answers 409 `dns.node.not_dns` (the controller of the e2e server has no dns role); with it
  // off, the routes are not registered (404 `sys.route_not_found`). The module list names DNS
  // either way, so the area is shown; the annotation `dns-log` notes which answer came.
  await page.route(MODULES, (route) => withDns(route));
  await page.goto("/dns/log");
  await expect(page.getByTestId("page-dns-log")).toBeVisible();
  const notDns = page.getByTestId("dns-log-not-dns");
  const off = page.getByTestId("dns-off");
  const noNode = page.getByTestId("dns-log-no-node");
  await expect(notDns.or(off).or(noNode)).toBeVisible();
  const answer = (await notDns.isVisible()) ? "not_dns" : (await off.isVisible()) ? "module_off" : "no_node";
  test.info().annotations.push({ type: "dns-log", description: answer });
  await expect(page.getByTestId("dns-log-table")).toHaveCount(0);
  await expect(page.getByTestId("dns-log-stop")).toHaveCount(0);
});
