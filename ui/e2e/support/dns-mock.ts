// Fakes for the DNS routes of the API, answered in the browser with `page.route`.
//
// WHY THE DNS SCENARIOS FAKE THE DNS ROUTES: WP4.5 builds the DNS views while WP4.2 builds the
// zone service and the handlers. Until WP4.2 lands, the real server answers every operation
// under `/api/v1/dns/` with 501 `sys.not_implemented` (one scenario of dns-zones.spec.ts proves
// what the pages show then). The other scenarios answer `/api/v1/dns/*` here, with the service
// of the mock API (`src/api/mock/dns-model.ts`, the same code the msw handlers and the unit
// tests run), and let everything else reach the real server: setup, sign-in, the shell, events.
// The import job is faked too (`/api/v1/jobs/<id>` of a job this fake started), and the module
// list is read from the server with `dns` added, so a server whose module answer lacks it does
// not hide the area. When WP4.2 has landed, these scenarios drop the fake and run against the
// real service (the lead's follow-up); the Rust route tests prove the service itself.
//
// A fake is installed before the first navigation and lives as long as the page. It records
// every request that is not a read (`sent`), so a test asserts what the UI sent.

import { randomBytes, randomUUID } from "node:crypto";
import type { Page, Route } from "@playwright/test";
import {
  changeRecords,
  createAcl,
  createKey,
  createZone,
  deleteAcl,
  deleteKey,
  deleteZone,
  DnsFailure,
  exportZoneFile,
  findAcl,
  findZone,
  importZoneFile,
  listRecords,
  listZones,
  seedDns,
  updateAcl,
  updateZone,
  type DnsContext,
  type DnsState,
} from "../../src/api/mock/dns-model";

/** A request the UI sent to a faked route (reads are not recorded). */
export interface Sent {
  method: string;
  /** The path, for example `/api/v1/dns/zones`. */
  path: string;
  /** The raw query string without the question mark. */
  query: string;
  /** The parsed JSON body, `null` when the request had none. */
  body: unknown;
}

const DNS = /\/api\/v1\/dns\//;
const JOBS = /\/api\/v1\/jobs\/[0-9a-f-]{36}(\?|$)/;
const MODULES = /\/api\/v1\/system\/modules(\?|$)/;

function hex(text: string): string {
  return Buffer.from(text, "utf8").toString("hex");
}

export class FakeDns {
  readonly sent: Sent[] = [];
  readonly state: DnsState;
  private revision = 1_000_000;
  private readonly jobs = new Map<string, unknown>();
  private readonly context: DnsContext;

  private constructor() {
    this.context = {
      now: () => Date.now(),
      nextRevision: () => ++this.revision,
      principal: () => ({ kind: "system", component: "api" }) as never,
      newId: () => randomUUID(),
      newSecret: () => randomBytes(32).toString("base64"),
    };
    this.state = seedDns(this.context);
  }

  /** Installs the fakes in `page`; call it before the first navigation. */
  static async install(page: Page): Promise<FakeDns> {
    const fake = new FakeDns();
    await page.route(DNS, (route) => fake.dns(route));
    await page.route(JOBS, (route) => fake.job(route));
    await page.route(MODULES, (route) => fake.modules(route));
    return fake;
  }

  /** The zone of this name in the fake's state. */
  zone(name: string) {
    return this.state.zones.find((z) => z.name === name);
  }

  /** The RRsets of a zone by name. */
  rrsets(zone: string) {
    const z = this.zone(zone);
    return z ? (this.state.rrsets.get(z.id) ?? []) : [];
  }

  private async modules(route: Route): Promise<void> {
    if (route.request().method() !== "GET") return route.fallback();
    const response = await route.fetch();
    const body = (await response.json()) as { running?: string[]; configured?: string[] };
    for (const key of ["running", "configured"] as const) {
      if (Array.isArray(body[key]) && !body[key].includes("dns")) body[key].push("dns");
    }
    await route.fulfill({ response, json: body });
  }

  private async job(route: Route): Promise<void> {
    const id = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    const detail = this.jobs.get(id);
    if (!detail) return route.fallback();
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(detail) });
  }

  private async dns(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const raw = request.postData();
    let body: Record<string, unknown> = {};
    if (raw) {
      try {
        body = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        body = {};
      }
    }
    if (method !== "GET") this.sent.push({ method, path: url.pathname, query: url.search.replace(/^\?/, ""), body: raw ? body : null });
    const ifMatch = request.headers()["if-match"];
    const revision = ifMatch && /^"?\d+"?$/.test(ifMatch) ? Number(ifMatch.replace(/"/g, "")) : null;
    try {
      await this.answer(route, method, url, body, revision);
    } catch (err) {
      if (err instanceof DnsFailure) {
        await route.fulfill({
          status: err.status,
          contentType: "application/problem+json",
          body: JSON.stringify({ type: "about:blank", status: err.status, code: err.code, title: "", detail: err.message, params: err.params }),
        });
        return;
      }
      throw err;
    }
  }

  private async answer(route: Route, method: string, url: URL, body: Record<string, unknown>, ifMatch: number | null): Promise<void> {
    const s = this.state;
    const c = this.context;
    const parts = url.pathname.replace(/^\/api\/v1\/dns\//, "").split("/").map(decodeURIComponent);
    const json = (status: number, value: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    const page = (items: unknown[]) => json(200, { items, next_cursor: null, revision: this.revision });
    const q = (name: string) => url.searchParams.get(name);
    const dryRun = q("dry_run") === "true";
    const [kind, id, sub, action] = parts;

    if (kind === "zones" && id === undefined) {
      if (method === "GET") return page(listZones(s));
      if (method === "POST") return json(201, createZone(s, c, body));
    }
    if (kind === "zones" && id !== undefined && sub === undefined) {
      if (method === "GET") return json(200, findZone(s, id));
      if (method === "PATCH") return json(200, updateZone(s, c, id, body, ifMatch));
      if (method === "DELETE") {
        deleteZone(s, c, id);
        return route.fulfill({ status: 204 });
      }
    }
    if (kind === "zones" && id !== undefined && sub === "records") {
      if (action === undefined && method === "GET") return page(listRecords(s, id, { name: q("name"), type: q("type"), origin: q("origin"), scope: q("scope") }));
      if (action === "batch" && method === "POST") return json(200, changeRecords(s, c, id, body, dryRun));
      if (action === "export" && method === "GET") return route.fulfill({ status: 200, contentType: "text/dns; charset=utf-8", body: exportZoneFile(s, id) });
      if (action === "import" && method === "POST") {
        if (dryRun) return json(200, importZoneFile(s, c, id, body, false));
        importZoneFile(s, c, id, body, false);
        const report = importZoneFile(s, c, id, body, true);
        const jobId = randomUUID();
        this.jobs.set(jobId, this.importJob(jobId, id, report));
        return route.fulfill({ status: 202, contentType: "application/json", headers: { Location: `/api/v1/jobs/${jobId}` }, body: JSON.stringify({ job_id: jobId }) });
      }
    }
    if (kind === "acls" && id === undefined) {
      if (method === "GET") return page([...s.acls].sort((a, b) => (a.name < b.name ? -1 : 1)));
      if (method === "POST") return json(201, createAcl(s, c, body));
    }
    if (kind === "acls" && id !== undefined) {
      if (method === "GET") return json(200, findAcl(s, id));
      if (method === "PATCH") return json(200, updateAcl(s, c, id, body, ifMatch));
      if (method === "DELETE") {
        deleteAcl(s, c, id);
        return route.fulfill({ status: 204 });
      }
    }
    if (kind === "keys" && id === undefined) {
      if (method === "GET") return page(s.keys);
      if (method === "POST") return json(201, createKey(s, c, body));
    }
    if (kind === "keys" && id !== undefined && method === "DELETE") {
      deleteKey(s, c, id);
      return route.fulfill({ status: 204 });
    }
    throw new DnsFailure(501, "sys.not_implemented", { method, path: url.pathname });
  }

  /** A finished import job shaped like the server's `JobDetail`, its report in the last step. */
  private importJob(id: string, zone: string, report: unknown): unknown {
    const at = new Date().toISOString();
    const by = { kind: "system", component: "api" };
    const steps = [
      { index: 0, kind: "dns.import.parse", state: { state: "done" }, started: at, finished: at },
      { index: 1, kind: "dns.import.apply", state: { state: "done" }, started: at, finished: at, output: hex(JSON.stringify(report)) },
    ];
    return {
      job: {
        id,
        state: "succeeded",
        created: { at, by },
        started: at,
        finished: at,
        revision: this.revision,
        spec: {
          kind: "dns.import",
          title: "jobs.title.dns_import",
          targets: [{ kind: "zone", id: zone }],
          timeout: 3600,
          steps: [
            { kind: "dns.import.parse", params: "" },
            { kind: "dns.import.apply", params: "" },
          ],
        },
        steps,
      },
      preview: null,
      revision: this.revision,
      transitions: [],
    };
  }
}
