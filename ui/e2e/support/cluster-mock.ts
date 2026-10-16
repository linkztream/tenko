// Fakes for the cluster routes of the API, answered in the browser with `page.route`.
//
// WHY THESE SCENARIOS FAKE THE CLUSTER ROUTES: the e2e server is one real controller. It cannot
// have a learner to promote, a second voter to hand leadership to, a member that is out of
// contact, a digest that differs, or a quorum to lose. So the scenarios that need such a cluster
// answer `/cluster/*`, `/queue*` and the quorum of `/system/status` here, and let the rest of
// the API (sign-in, IPAM, the plan dialog's dry run, events) reach the real server. What the
// tests prove with these fakes is the UI: which preview a dialog shows, what it sends (method,
// path and body, and nothing before the person confirms), and how the page, the banner and the
// queue view follow the answers. The real behaviour of the cluster is proven elsewhere: the Rust
// lab tests `crates/tenko/tests/acceptance_cluster.rs` (membership, step-down, digests) and
// `crates/tenko/tests/acceptance_partition.rs` (isolation, the queue, the heal).
//
// The bodies are shaped like the mock API's (`src/api/mock/cluster-store.ts`, `routes-cluster.ts`)
// and like the schemas of `docs/api/openapi.json` (`ClusterView`, `MemberView`, `StepDown`,
// `DigestReport`, `QueueItemView`, `QueuedChangeView`). Error answers are problem documents with
// the codes of the server (`cluster.member.*`, `queue.*`, `cluster.no_quorum`). Documentation
// values only: names under example.test, addresses from 192.0.2.0/24.
//
// A fake is installed before the first navigation and lives as long as the page. It records
// every request that is not a read (`sent`), so a test asserts what the UI sent.

import { randomUUID } from "node:crypto";
import type { Page, Route } from "@playwright/test";
import type { Api, Schemas } from "./api";

type ClusterView = Schemas["ClusterView"];
type MemberView = Schemas["MemberView"];
type QuorumView = Schemas["QuorumView"];
type QueueItemView = Schemas["QueueItemView"];
type QueuedChangeView = Schemas["QueuedChangeView"];

/** A request the UI sent to a faked route (reads are not recorded). */
export interface Sent {
  method: string;
  /** The full path, for example `/api/v1/cluster/members/3/promote`. */
  path: string;
  /** The raw query string without the question mark. */
  query: string;
  /** The parsed JSON body, `null` when the request had none. */
  body: unknown;
}

/** A member of the faked cluster. */
export interface MemberSpec {
  node: number;
  role?: "voter" | "learner";
  leader?: boolean;
  /** Log entries behind the leader; ignored for the leader. Default 0. */
  lag?: number;
  /** Milliseconds since the leader heard from it; ignored for the leader. Default 40. */
  contactMs?: number;
  name?: string;
}

/** What `FakeCluster.install` starts from. */
export interface Seed {
  members?: MemberSpec[];
  /** The controller that answers (the browser talks to it). Default: the leader. */
  node?: number;
  term?: number;
}

/** A member with the figures of a healthy follower; `leader: true` makes it the leader. */
export function member(node: number, spec: Omit<MemberSpec, "node"> = {}): MemberSpec {
  return { node, ...spec };
}

/** Three voters (node 1 leads, nodes 2 and 3 follow, 3 two entries behind) and no learner. */
export function threeVoters(): MemberSpec[] {
  return [member(1, { leader: true }), member(2, { lag: 0, contactMs: 40 }), member(3, { lag: 2, contactMs: 60 })];
}

/** A caught-up learner at the end of three voters. */
export function threeVotersAndLearner(lag = 0): MemberSpec[] {
  return [...threeVoters(), member(4, { role: "learner", lag, contactMs: 80 })];
}

/** The caught-up limit of the UI: a follower within this many entries and in contact counts as caught up. */
const CAUGHT_UP_ENTRIES = 100;
const CONTACT_LOST_MS = 10_000;

const iso = (at: number): string => new Date(at).toISOString();
const DAY = 86_400_000;

function nameOf(node: number): string {
  return `ctl-${node}.example.test`;
}

function build(spec: MemberSpec, now: number): MemberView {
  const leader = spec.leader === true;
  return {
    node: spec.node,
    name: spec.name ?? nameOf(spec.node),
    address: `192.0.2.${10 + spec.node}:8444`,
    role: spec.role ?? "voter",
    leader,
    version: "0.1.0",
    data_format: 3,
    protocol_majors: [1, 2],
    raft_wire: "openraft-0.9/cbor-1",
    formats: [2, 3],
    joined_at: iso(now - 5 * DAY),
    matched: leader ? 1000 : 1000 - (spec.lag ?? 0),
    lag_entries: leader ? null : (spec.lag ?? 0),
    last_contact_ms: leader ? null : (spec.contactMs ?? 40),
  };
}

function caughtUp(m: MemberView): boolean {
  return m.leader || ((m.last_contact_ms ?? 0) <= CONTACT_LOST_MS && (m.lag_entries ?? 0) <= CAUGHT_UP_ENTRIES);
}

function emptyPlan(): QueueItemView["plan"] {
  return {
    base_revision: 1,
    changes: [],
    results: [],
    summary: { counts: [], lines: [], mutations: 0, preconditions: 0, unacknowledged: [], warnings: {} },
    warnings: [],
  } as unknown as QueueItemView["plan"];
}

interface Problem {
  status: number;
  code: string;
  detail: string;
  params?: Record<string, string>;
}

/** The refusal of one membership rule, with the status and code the server answers. */
const RULES: Record<string, Problem> = {
  single: { status: 409, code: "cluster.single", detail: "the controller is not part of a cluster" },
  changing: { status: 409, code: "cluster.member.changing", detail: "another membership change is in progress" },
  not_learner: { status: 409, code: "cluster.member.not_learner", detail: "the member is not a learner" },
  even_voters: { status: 409, code: "cluster.member.even_voters", detail: "the result would have an even number of voters; force to proceed" },
  not_caught_up: { status: 409, code: "cluster.member.not_caught_up", detail: "the learner is behind the leader; force to proceed" },
  last_voter: { status: 409, code: "cluster.member.last_voter", detail: "the change would remove the last voter" },
  no_successor: { status: 409, code: "cluster.member.no_successor", detail: "no other voter is caught up" },
};

function notFound(node: number): Problem {
  return { status: 404, code: "cluster.member.not_found", detail: `no member has the id ${node}`, params: { id: String(node) } };
}

/** Routes that write IPAM objects; the quorum gate refuses them while the controller is isolated. */
const GATED = /\/api\/v1\/(tenants|vrfs|sites|vlans|prefixes|ranges|addresses|hosts)(\/|\?|$)/;

export class FakeCluster {
  /** Every request to a faked route that was not a read, oldest first. */
  readonly sent: Sent[] = [];

  private view: ClusterView;
  private queue: Array<{ item: QueueItemView; request: { method: string; path: string; query?: string | null; body?: unknown } }> = [];
  private changes: QueuedChangeView[] = [];
  private digestMismatch: number | null = null;
  private readonly refusals: Array<{ method: string; pattern: RegExp; problem: Problem }> = [];

  private constructor(seed: Seed) {
    const now = Date.now();
    const specs = seed.members ?? threeVoters();
    const members = specs.map((spec) => build(spec, now));
    const leader = members.find((m) => m.leader)?.node ?? null;
    this.view = {
      node: seed.node ?? leader ?? members[0]!.node,
      term: seed.term ?? 7,
      quorum: { state: members.length > 1 ? "healthy" : "single" },
      changing: false,
      leader,
      members,
    };
  }

  /** Installs the fakes in `page`; call it before the first navigation. */
  static async install(page: Page, seed: Seed = {}): Promise<FakeCluster> {
    const fake = new FakeCluster(seed);
    // Later routes win in Playwright, and `fallback` passes a request to the earlier ones and to
    // the network, so the gate and the status only touch what they mean to.
    await page.route(/\/api\/v1\/(cluster|queue)(\/|\?|$)/, (route) => fake.cluster(route));
    await page.route(GATED, (route) => fake.gate(route));
    await page.route(/\/api\/v1\/system\/status(\?|$)/, (route) => fake.status(route));
    return fake;
  }

  // -- the state the tests drive --------------------------------------------------------------

  /** The members as the faked `GET /cluster/members` lists them. */
  members(): MemberView[] {
    return this.view.members.map((m) => ({ ...m }));
  }

  /** Replaces the members (a change made elsewhere); the page shows it after the next cluster event. */
  setMembers(specs: MemberSpec[]): void {
    const now = Date.now();
    this.view = { ...this.view, members: specs.map((spec) => build(spec, now)), leader: specs.find((s) => s.leader)?.node ?? null };
    this.view.quorum = { state: specs.length > 1 ? "healthy" : "single" };
  }

  /** Makes `node` report another state digest; `null`: every member agrees. */
  setDigestMismatch(node: number | null): void {
    this.digestMismatch = node;
  }

  /** The next request with `method` to a path matching `pattern` is refused with `problem`. */
  refuseNext(method: string, pattern: RegExp, problem: Problem): void {
    this.refusals.push({ method: method.toUpperCase(), pattern, problem });
  }

  /** Marks a membership change as in progress (`changing`), which the rules refuse a second change for. */
  setChanging(changing: boolean): void {
    this.view = { ...this.view, changing };
  }

  /** The controller loses its quorum: writes to IPAM are refused with 503 `cluster.no_quorum`. */
  isolate(minutesAgo = 4): void {
    const since = iso(Date.now() - minutesAgo * 60_000);
    this.view = { ...this.view, quorum: { state: "isolated", since, last_contact: since, applied: 1000 } };
  }

  /** The controller is electing a leader: writes are refused too, with a shorter retry hint. */
  elect(): void {
    this.view = { ...this.view, quorum: { state: "electing", since: iso(Date.now() - 20_000) } };
  }

  /**
   * The quorum is back and the queue drains: an item applies, unless its key (the prefix) is in
   * `conflicting`, which settles as a conflict whose plan changed.
   */
  heal(conflicting: string[] = []): void {
    this.view = { ...this.view, quorum: { state: this.view.members.length > 1 ? "healthy" : "single" } };
    const at = iso(Date.now());
    for (const { item, request } of this.queue) {
      const conflict = conflicting.includes(item.summary.key ?? "");
      this.changes.push({
        id: item.id,
        author: "0190d1c2-0000-7000-8000-000000000001",
        principal: { kind: "user", id: "0190d1c2-0000-7000-8000-000000000001", session: "e2e-session", strength: "password" },
        commands: [],
        queued_at: item.queued_at,
        queued_on: item.queued_on,
        queued_plan: item.plan,
        request: { method: request.method, path: request.path, query: request.query ?? null, body: request.body ?? null, if_match: null },
        settled_at: at,
        state: conflict ? "conflict" : "applied",
        summary: item.summary,
        revision: 1000,
        ...(conflict
          ? {
              conflict: { code: "queue.plan_changed", status: 409, detail: "the plan after the heal differs from the queued plan", params: {} },
              current_plan: emptyPlan(),
            }
          : {}),
      } as unknown as QueuedChangeView);
    }
    this.queue = [];
  }

  /** The items of the local queue as the faked `GET /queue` lists them. */
  queued(): QueueItemView[] {
    return this.queue.map((q) => q.item);
  }

  /** The settled changes as the faked `GET /queue/conflicts` lists them. */
  settled(): QueuedChangeView[] {
    return [...this.changes];
  }

  /**
   * Makes the shell read the status again: the real server announces a change of the backup
   * settings on its `system` topic, and the shell answers a `system` event with a new
   * `GET /system/status`, which this fake answers with the current quorum. (Without it the shell
   * reads the status when the page loads and every 30 s.) Needs the signed-in administrator
   * within five minutes of the sign-in.
   */
  async refreshShell(api: Api): Promise<void> {
    const status = await api.get<Schemas["BackupStatusView"]>("/system/backups");
    const { settings } = status;
    await api.put("/system/backups/settings", {
      enabled: settings.enabled,
      include_config: settings.include_config,
      interval_hours: settings.interval_hours,
      keep: settings.keep >= 50 ? 7 : settings.keep + 1,
      recipient: settings.recipient ?? null,
      target_dir: settings.target_dir ?? null,
    });
  }

  /**
   * Makes an open queue view read its lists again: the real server announces the drain of the queue
   * on the `ipam` topic (the table of queued changes changes), and so does any IPAM write; this
   * one creates a prefix inside 192.0.2.0/24 that no scenario looks at.
   */
  async refreshQueue(api: Api): Promise<void> {
    this.spare += 1;
    await api.post("/prefixes", { cidr: `192.0.2.${16 * this.spare}/28`, description: "spare" });
  }

  private spare = 0;

  /** Makes the cluster page read the members again: the real server announces a new enrolment on `cluster`. */
  async refreshCluster(api: Api): Promise<void> {
    await api.post("/nodes/enrolments", { name: `e2e-${randomUUID().slice(0, 8)}`, roles: ["probe"] }, { idempotencyKey: null });
  }

  // -- the routes --------------------------------------------------------------------------

  private record(route: Route, url: URL): Sent {
    const request = route.request();
    let body: unknown = null;
    const text = request.postData();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }
    const sent = { method: request.method(), path: url.pathname, query: url.search.replace(/^\?/, ""), body };
    if (request.method() !== "GET") this.sent.push(sent);
    return sent;
  }

  private async answer(route: Route, status: number, body: unknown): Promise<void> {
    if (status === 204) return route.fulfill({ status });
    return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
  }

  private async refuse(route: Route, problem: Problem): Promise<void> {
    await route.fulfill({
      status: problem.status,
      contentType: "application/problem+json",
      body: JSON.stringify({
        type: "about:blank",
        status: problem.status,
        code: problem.code,
        title: problem.code,
        detail: problem.detail,
        params: problem.params ?? {},
      }),
    });
  }

  private async cluster(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const method = request.method();
    const sent = this.record(route, url);

    const index = this.refusals.findIndex((r) => r.method === method && r.pattern.test(url.pathname));
    if (index >= 0) return this.refuse(route, this.refusals.splice(index, 1)[0]!.problem);

    if (method === "GET" && path === "/cluster/members") return this.answer(route, 200, this.view);
    if (method === "GET" && path === "/cluster/digests") return this.answer(route, 200, this.digests());
    let match = /^\/cluster\/members\/(\d+)\/promote$/.exec(path);
    if (method === "POST" && match) return this.promote(route, Number(match[1]), (sent.body ?? {}) as { force?: boolean; replace?: number });
    match = /^\/cluster\/members\/(\d+)$/.exec(path);
    if (method === "DELETE" && match) return this.remove(route, Number(match[1]));
    if (method === "POST" && path === "/cluster/step-down") return this.stepDown(route);

    if (method === "GET" && path === "/queue") return this.answer(route, 200, { items: this.queued() });
    if (method === "POST" && path === "/queue") return this.enqueue(route, sent.body as { method: string; path: string; query?: string | null; body?: unknown });
    match = /^\/queue\/([0-9a-f-]{36})$/.exec(path);
    if (method === "DELETE" && match) {
      const found = this.queue.findIndex((q) => q.item.id === match![1]);
      if (found < 0) return this.refuse(route, { status: 404, code: "queue.not_found", detail: "no queued change of yours has this id" });
      this.queue.splice(found, 1);
      return this.answer(route, 204, null);
    }
    if (method === "GET" && path === "/queue/conflicts") return this.answer(route, 200, { items: this.changes, revision: 1000 });
    match = /^\/queue\/conflicts\/([0-9a-f-]{36})(\/reapply)?$/.exec(path);
    if (match) {
      const found = this.changes.findIndex((c) => c.id === match![1]);
      if (found < 0) return this.refuse(route, { status: 404, code: "queue.not_found", detail: "no queued change of yours has this id" });
      if (method === "DELETE" && !match[2]) {
        this.changes.splice(found, 1);
        return this.answer(route, 204, null);
      }
      if (method === "POST" && match[2]) {
        if (url.searchParams.get("dry_run") === "true") {
          return this.answer(route, 200, { dry_run: true, plan: emptyPlan(), warnings: [], revision: null });
        }
        this.changes.splice(found, 1);
        return this.answer(route, 200, { dry_run: false, warnings: [], job_id: randomUUID(), revision: 1001 });
      }
    }
    return route.fallback();
  }

  private voters(): MemberView[] {
    return this.view.members.filter((m) => m.role === "voter");
  }

  /** The first refusal of a change, or null; `force` overrides the two that can be forced. */
  private blocker(kind: "promote" | "remove" | "stepdown", node: number, options: { force?: boolean; replace?: number } = {}): Problem | null {
    const view = this.view;
    if (view.members.length <= 1) return RULES.single!;
    if (view.changing) return RULES.changing!;
    const target = view.members.find((m) => m.node === node);
    const voters = this.voters().length;
    if (kind === "remove") {
      if (target?.role === "voter" && voters <= 1) return RULES.last_voter!;
      return null;
    }
    if (kind === "stepdown") {
      return this.successor() ? null : RULES.no_successor!;
    }
    if (!target || target.role !== "learner") return RULES.not_learner!;
    const replaced = options.replace != null ? view.members.find((m) => m.node === options.replace && m.role === "voter") : undefined;
    if (options.replace != null && !replaced) return notFound(options.replace);
    if (!options.force) {
      const after = voters + 1 - (replaced ? 1 : 0);
      if (after % 2 === 0) return RULES.even_voters!;
      if (!caughtUp(target)) return RULES.not_caught_up!;
    }
    return null;
  }

  /** The most caught-up other voter in contact: who leads after a step-down. */
  private successor(): MemberView | undefined {
    return this.voters()
      .filter((m) => !m.leader && caughtUp(m))
      .sort((a, b) => (a.lag_entries ?? 0) - (b.lag_entries ?? 0) || (a.last_contact_ms ?? 0) - (b.last_contact_ms ?? 0) || a.node - b.node)[0];
  }

  private async promote(route: Route, node: number, body: { force?: boolean; replace?: number }): Promise<void> {
    if (!this.view.members.some((m) => m.node === node)) return this.refuse(route, notFound(node));
    const problem = this.blocker("promote", node, body);
    if (problem) return this.refuse(route, problem);
    const members = this.view.members
      .filter((m) => m.node !== body.replace)
      .map((m) => (m.node === node ? { ...m, role: "voter" as const } : m));
    this.view = { ...this.view, members };
    return this.answer(route, 200, { ...this.view, job_id: randomUUID() });
  }

  private async remove(route: Route, node: number): Promise<void> {
    if (!this.view.members.some((m) => m.node === node)) return this.refuse(route, notFound(node));
    const problem = this.blocker("remove", node);
    if (problem) return this.refuse(route, problem);
    let members = this.view.members.filter((m) => m.node !== node);
    let { leader, term } = this.view;
    if (leader === node) {
      const next = members.filter((m) => m.role === "voter").sort((a, b) => (a.lag_entries ?? 0) - (b.lag_entries ?? 0) || a.node - b.node)[0];
      leader = next?.node ?? null;
      term += 1;
      members = members.map((m) => (m.node === leader ? { ...m, leader: true, lag_entries: null, last_contact_ms: null } : m));
    }
    this.view = { ...this.view, members, leader, term, node: this.view.node === node && leader != null ? leader : this.view.node };
    return this.answer(route, 200, { ...this.view, job_id: randomUUID() });
  }

  private async stepDown(route: Route): Promise<void> {
    const problem = this.blocker("stepdown", this.view.node);
    if (problem) return this.refuse(route, problem);
    const next = this.successor()!;
    const previous = this.view.leader!;
    const term = this.view.term + 1;
    const members = this.view.members.map((m) => {
      if (m.node === previous) return { ...m, leader: false, lag_entries: 0, last_contact_ms: 40 };
      if (m.node === next.node) return { ...m, leader: true, lag_entries: null, last_contact_ms: null };
      return m;
    });
    this.view = { ...this.view, members, leader: next.node, term };
    return this.answer(route, 200, { previous, leader: next.node, term });
  }

  /** A deterministic 64-digit digest per node and revision; the mismatching node holds other data. */
  private digests(): Schemas["DigestReport"] {
    const revision = 1000;
    const digest = (seed: string): string => {
      let out = "";
      let h = 0x811c9dc5;
      for (let round = 0; out.length < 64; round += 1) {
        for (const ch of `${seed}/${round}`) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
        out += h.toString(16).padStart(8, "0");
      }
      return out.slice(0, 64);
    };
    const members = this.view.members.map((m) => ({
      node: m.node,
      sha256: digest(m.node === this.digestMismatch ? `${revision}/diverged/${m.node}` : String(revision)),
      revision,
      tables: 41,
      entries: 2000 + revision,
    }));
    return { revision, agree: this.digestMismatch == null || !this.view.members.some((m) => m.node === this.digestMismatch), members } as Schemas["DigestReport"];
  }

  private async enqueue(route: Route, body: { method: string; path: string; query?: string | null; body?: unknown }): Promise<void> {
    const quorum: QuorumView = this.view.quorum;
    if (quorum.state !== "isolated" && quorum.state !== "electing") {
      return this.refuse(route, { status: 409, code: "queue.not_isolated", detail: "the controller is in contact with a quorum; send the write itself", params: { state: quorum.state } });
    }
    const fields = body.body && typeof body.body === "object" ? (body.body as Record<string, unknown>) : {};
    const key = ["address", "cidr", "fqdn", "name"].map((k) => fields[k]).find((v): v is string => typeof v === "string" && v !== "");
    const collection = body.path.split("/")[1] ?? "";
    const kinds: Record<string, string> = { prefixes: "prefix", addresses: "address", hosts: "host", vlans: "vlan", sites: "site", tenants: "tenant", vrfs: "vrf", ranges: "range" };
    const now = Date.now();
    const item: QueueItemView = {
      id: randomUUID(),
      queued_at: iso(now),
      queued_on: this.view.node,
      method: body.method,
      path: body.path,
      summary: { action: body.method === "POST" ? "create" : body.method === "DELETE" ? "delete" : "update", kind: kinds[collection] ?? "address", ...(key ? { key } : {}) },
      plan: emptyPlan(),
      expires_at: iso(now + 7 * DAY),
      state: "queued",
    } as unknown as QueueItemView;
    this.queue.push({ item, request: body });
    return this.answer(route, 201, item);
  }

  /** The quorum gate: a write to IPAM is refused with 503 `cluster.no_quorum` while isolated; a dry run passes. */
  private async gate(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const quorum = this.view.quorum;
    const refusing = quorum.state === "isolated" || quorum.state === "electing";
    if (!refusing || ["GET", "HEAD", "OPTIONS"].includes(request.method()) || url.searchParams.get("dry_run") === "true") {
      return route.fallback();
    }
    this.record(route, url);
    await route.fulfill({
      status: 503,
      contentType: "application/problem+json",
      headers: { "Retry-After": quorum.state === "electing" ? "5" : "15" },
      body: JSON.stringify({
        type: "about:blank",
        status: 503,
        code: "cluster.no_quorum",
        title: "No quorum",
        detail: "this controller is not in contact with a quorum; writes are refused",
        params: { since: quorum.since ?? iso(Date.now()), state: quorum.state, revision: String(quorum.applied ?? 1000), queueable: "true" },
      }),
    });
  }

  /** The real status of the server, with the quorum the fake holds. */
  private async status(route: Route): Promise<void> {
    const response = await route.fetch();
    if (!response.ok()) return route.fulfill({ response });
    const body = (await response.json()) as { store?: Record<string, unknown> };
    body.store = { ...(body.store ?? {}), quorum: this.view.quorum };
    await route.fulfill({ response, json: body });
  }
}
