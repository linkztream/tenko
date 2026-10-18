// Fakes for the resolver side of the DNS routes (WP5.5), answered in the browser with `page.route`.
//
// WHY THESE SCENARIOS FAKE THE ROUTES: the e2e server is one controller without the `dns` role
// (support/server.ts writes `roles = "controller"`), whose DNS module may not run, and WP5.2
// builds the block list routes (and `PUT /dns/lists/{id}/file`) at the same time as the pages.
// The fake answers `/api/v1/dns/forwarders`, `/api/v1/dns/lists` (with "fetch now" and the
// file upload as jobs it serves itself), `/api/v1/nodes/<id>/dns` and the module list with
// `dns` added, with the service of the mock API (`src/api/mock/dns-resolver-model.ts`, the same
// code the msw handlers and the unit tests run), and lets everything else reach the real
// server. The forwarder routes are real since WP5.1: one scenario of dns-forwarders.spec.ts
// runs against them. The Rust route tests prove the services themselves.
//
// A fake is installed before the first navigation and lives as long as the page; `sent`
// records every request that is not a read.

import { randomUUID } from "node:crypto";
import type { Page, Route } from "@playwright/test";
import { DnsFailure, type DnsContext } from "../../src/api/mock/dns-model";
import {
  createForwarder,
  createList,
  deleteForwarder,
  deleteList,
  fetchList,
  findForwarder,
  findList,
  listForwarders,
  listLists,
  resolverStatus,
  seedResolver,
  updateForwarder,
  updateList,
  uploadList,
  type ResolverState,
} from "../../src/api/mock/dns-resolver-model";

/** A request the UI sent to a faked route (reads are not recorded). */
export interface Sent {
  method: string;
  path: string;
  /** The body: parsed JSON, the text of a file upload, or null. */
  body: unknown;
  ifMatch: string | null;
}

export interface FakeOptions {
  /** How the node's DNS status answers: the role runs (default), 409 `dns.node.not_dns`, or 404 with the module off. */
  node?: "dns" | "not_dns" | "module_off";
}

const FORWARDERS = /\/api\/v1\/dns\/forwarders(\/[^?]*)?(\?|$)/;
const LISTS = /\/api\/v1\/dns\/lists(\/[^?]*)?(\?|$)/;
const NODE = /\/api\/v1\/nodes\/\d+\/dns(\?|$)/;
const JOBS = /\/api\/v1\/jobs\/[0-9a-f-]{36}(\?|$)/;
const MODULES = /\/api\/v1\/system\/modules(\?|$)/;
const STATUS = /\/api\/v1\/system\/status(\?|$)/;

export class FakeResolver {
  readonly sent: Sent[] = [];
  readonly state: ResolverState;
  private revision = 2_000_000;
  private readonly jobs = new Map<string, unknown>();
  private readonly context: DnsContext;

  private constructor(private readonly options: FakeOptions) {
    this.context = {
      now: () => Date.now(),
      nextRevision: () => ++this.revision,
      principal: () => ({ kind: "system", component: "api" }) as never,
      newId: () => randomUUID(),
      newSecret: () => "",
    };
    this.state = seedResolver(this.context);
  }

  /** Installs the fakes in `page`; call it before the first navigation. */
  static async install(page: Page, options: FakeOptions = {}): Promise<FakeResolver> {
    const fake = new FakeResolver(options);
    await page.route(FORWARDERS, (route) => fake.handle(route));
    await page.route(LISTS, (route) => fake.handle(route));
    await page.route(NODE, (route) => fake.handle(route));
    await page.route(JOBS, (route) => fake.job(route));
    await page.route(MODULES, (route) => withDns(route, options.node === "module_off"));
    await page.route(STATUS, (route) => fake.status(route));
    return fake;
  }

  list(name: string) {
    return this.state.lists.find((l) => l.name === name);
  }

  rule(suffix: string) {
    return this.state.forwarders.find((r) => r.suffix === suffix);
  }

  /** The node of the server with an id, and the `dns` role while the fake says the role runs. */
  private async status(route: Route): Promise<void> {
    const response = await route.fetch();
    const body = (await response.json()) as { node?: { id?: number | null; roles?: string[] } };
    if (body.node) {
      if (body.node.id === null || body.node.id === undefined) body.node.id = 1;
      const roles = body.node.roles ?? [];
      if ((this.options.node ?? "dns") === "dns" && !roles.includes("dns")) body.node.roles = [...roles, "dns"];
    }
    await route.fulfill({ response, json: body });
  }

  private async job(route: Route): Promise<void> {
    const id = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    const detail = this.jobs.get(id);
    if (!detail) return route.fallback();
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(detail) });
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const raw = request.postData();
    let body: unknown = null;
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }
    const ifMatchHeader = request.headers()["if-match"] ?? null;
    if (method !== "GET") this.sent.push({ method, path: url.pathname, body, ifMatch: ifMatchHeader });
    const ifMatch = ifMatchHeader && /^"?\d+"?$/.test(ifMatchHeader) ? Number(ifMatchHeader.replace(/"/g, "")) : null;
    const json = (status: number, value: unknown, headers?: Record<string, string>) =>
      route.fulfill({ status, contentType: "application/json", headers, body: JSON.stringify(value) });
    const problem = (status: number, code: string, params: Record<string, string> = {}) =>
      route.fulfill({
        status,
        contentType: "application/problem+json",
        body: JSON.stringify({ type: "about:blank", status, code, title: "", detail: code, params }),
      });
    try {
      if (NODE.test(url.pathname + url.search)) {
        if (method !== "GET") return await route.fallback();
        if (this.options.node === "not_dns") return await problem(409, "dns.node.not_dns", { node: "1" });
        if (this.options.node === "module_off") return await problem(404, "sys.route_not_found");
        return await json(200, {
          node: 1,
          serving: true,
          revision: this.revision,
          lag: 0,
          zones: 2,
          rrsets: 14,
          listeners: [
            { address: "192.0.2.53:53", transport: "udp", workers: 2 },
            { address: "192.0.2.53:53", transport: "tcp", workers: 0 },
          ],
          socket_mode: "shared",
          tcp_open: 0,
          tcp_refused: 0,
          started: new Date().toISOString(),
          ...resolverStatus(this.state),
        });
      }
      if (this.options.node === "module_off") return await problem(404, "sys.route_not_found");
      const parts = url.pathname.replace(/^\/api\/v1\/dns\//, "").split("/").map(decodeURIComponent);
      const [kind, id, action] = parts;
      const s = this.state;
      const c = this.context;
      const page = (items: unknown[]) => json(200, { items, next_cursor: null, revision: this.revision });
      const input = (body ?? {}) as Record<string, unknown>;
      if (kind === "forwarders") {
        if (id === undefined && method === "GET") return await page(listForwarders(s));
        if (id === undefined && method === "POST") return await json(201, createForwarder(s, c, input));
        if (id !== undefined && method === "GET") return await json(200, findForwarder(s, id));
        if (id !== undefined && method === "PATCH") return await json(200, updateForwarder(s, c, id, input, ifMatch));
        if (id !== undefined && method === "DELETE") {
          deleteForwarder(s, id, ifMatch);
          return await route.fulfill({ status: 204 });
        }
      }
      if (kind === "lists") {
        if (id === undefined && method === "GET") return await page(listLists(s));
        if (id === undefined && method === "POST") return await json(201, createList(s, c, input));
        if (id !== undefined && action === undefined && method === "GET") return await json(200, findList(s, id));
        if (id !== undefined && action === undefined && method === "PATCH") return await json(200, updateList(s, c, id, input, ifMatch));
        if (id !== undefined && action === undefined && method === "DELETE") {
          deleteList(s, id, ifMatch);
          return await route.fulfill({ status: 204 });
        }
        if (id !== undefined && action === "fetch" && method === "POST") {
          fetchList(s, c, id);
          return await this.started(route, id, "fetch");
        }
        if (id !== undefined && action === "file" && method === "PUT") {
          uploadList(s, c, id, typeof body === "string" ? body : (raw ?? ""), ifMatch);
          return await this.started(route, id, "upload");
        }
      }
      return await problem(501, "sys.not_implemented", { method, path: url.pathname });
    } catch (err) {
      if (err instanceof DnsFailure) return await problem(err.status, err.code, err.params);
      throw err;
    }
  }

  /** Answers 202 with a finished job shaped like the server's `JobDetail`. */
  private async started(route: Route, list: string, kind: "fetch" | "upload"): Promise<void> {
    const id = randomUUID();
    const at = new Date().toISOString();
    const by = { kind: "system", component: "api" };
    const kinds = [kind === "fetch" ? "dns.list.fetch" : "dns.list.read", "dns.list.compile"];
    this.jobs.set(id, {
      job: {
        id,
        state: "succeeded",
        created: { at, by },
        started: at,
        finished: at,
        revision: this.revision,
        spec: {
          kind: `dns.list.${kind}`,
          title: `jobs.title.dns_list_${kind}`,
          targets: [{ kind: "dns_list", id: list }],
          timeout: 600,
          steps: kinds.map((k) => ({ kind: k, params: "" })),
        },
        steps: kinds.map((k, index) => ({ index, kind: k, state: { state: "done" }, started: at, finished: at })),
      },
      preview: null,
      revision: this.revision,
      transitions: [],
    });
    await route.fulfill({ status: 202, contentType: "application/json", headers: { Location: `/api/v1/jobs/${id}` }, body: JSON.stringify({ job_id: id }) });
  }
}

/** The module list of the real server with DNS added (or taken out), so the area is shown or not. */
export async function withDns(route: Route, off = false): Promise<void> {
  if (route.request().method() !== "GET") return route.fallback();
  const response = await route.fetch();
  const body = (await response.json()) as { running?: string[]; configured?: string[] };
  for (const key of ["running", "configured"] as const) {
    if (!Array.isArray(body[key])) continue;
    if (off) body[key] = body[key].filter((m) => m !== "dns");
    else if (!body[key].includes("dns")) body[key].push("dns");
  }
  await route.fulfill({ response, json: body });
}
