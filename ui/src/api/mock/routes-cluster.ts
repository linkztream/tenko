// Mock routes of the `cluster` API area (OPS-03, OPS-26, WP3.1a and WP3.9): the members of the
// controller cluster and their changes, the state digests, the quorum gate that refuses writes
// while the controller is isolated, and the local queue of writes held back until the heal
// (pending operations, see cluster/model.ts). The state is cluster-store.ts.
//
// Simplifications: a membership change completes at once (the answer carries a job id, no job
// exists); a queued change is planned against nothing (its plan is empty); `Idempotency-Key`
// is not looked at.
import { http, type HttpHandler } from "msw";
import {
  promotePreview,
  removePreview,
  stepDownPreview,
  type Blocker,
  type ChangePreview,
  type ClusterView,
  type DigestReport,
  type MemberDigest,
  type QueueItem,
  type QueuedChange,
  type ReapplyResult,
  type WriteMethod,
} from "../../cluster/model";
import { requireAdmin, requireSession } from "./auth";
import { clusterState, clusterView, noQuorum, QUEUE_LIFETIME_MS, type StoredChange } from "./cluster-store";
import { commit, db } from "./db";
import { nodeRef } from "./nodes-store";
import { Problem, created, fail, noContent, ok, type ProblemBody, type Reply } from "./reply";
import { paginate, route, type MockContext } from "./route";
import { iso, isUuid, randomId } from "./util";

type Awaitable<T> = T | Promise<T>;
type QueueMethod = "get" | "post" | "delete";
interface QueueMockContext extends Omit<MockContext<QueueMethod, never>, "params" | "body" | "optionalBody"> {
  readonly params: Record<"id", string>;
  body(): Promise<Record<string, unknown>>;
  optionalBody(): Promise<Record<string, unknown>>;
}

/**
 * The queue routes of WP3.9, typed by the UI's working model in `cluster/model.ts` rather than by
 * the document, until WP3.11c moves the views and this mock to the generated types.
 */
function queueRoute(
  method: QueueMethod,
  path: string,
  resolver: (ctx: QueueMockContext) => Awaitable<Reply<unknown> | Response>,
): HttpHandler {
  return route(method as never, path as never, resolver as never);
}

const WRITE_METHODS: readonly WriteMethod[] = ["post", "put", "patch", "delete"];
const API_PREFIX = "/api/v1/";

function invalidRequest(detail: string, field?: string): Problem {
  return new Problem("sys.invalid_request", { status: 400, detail, params: field ? { field } : {} });
}

function clusterProblem(code: string, status: number, detail: string, params: Record<string, string> = {}): Problem {
  return new Problem(code, { status, detail, params });
}

function parseNode(raw: string): number {
  const id = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(id) || id <= 0) throw invalidRequest("the member identifier is not a positive number", "id");
  return id;
}

function notFound(node: number): Problem {
  return clusterProblem("cluster.member.not_found", 404, `no member has the id ${node}`, { id: String(node) });
}

const BLOCKER_CODES: Record<Blocker, [code: string, detail: string]> = {
  single: ["cluster.single", "the controller is not part of a cluster"],
  changing: ["cluster.member.changing", "another membership change is in progress"],
  not_learner: ["cluster.member.not_learner", "the member is not a learner"],
  not_voter: ["cluster.member.not_found", "the voter to replace is not a member"],
  even_voters: ["cluster.member.even_voters", "the result would have an even number of voters; force to proceed"],
  not_caught_up: ["cluster.member.not_caught_up", "the learner is behind the leader; force to proceed"],
  last_voter: ["cluster.member.last_voter", "the change would remove the last voter"],
  no_successor: ["cluster.member.no_successor", "no other voter is caught up"],
};

/** Fails with the 409 (404 for a missing voter to replace) of the first refusal of `preview`. */
function refuse(preview: ChangePreview, force = false): void {
  const first = preview.blockers[0] ?? (force ? undefined : preview.forceable[0]);
  if (!first) return;
  const [code, detail] = BLOCKER_CODES[first];
  throw clusterProblem(code, first === "not_voter" ? 404 : 409, detail, { blocker: first });
}

/** Records a change of the member table; returns the view to answer with a fresh job. */
function changed(nodes: number[]): ClusterView {
  commit("cluster", { objects: nodes.map(nodeRef), tables: ["cluster.members"] });
  return { ...clusterView(), job_id: randomId() };
}

// ---------------------------------------------------------------------------------
// Members

const listMembers = route("get", "/api/v1/cluster/members", () => {
  requireSession();
  return ok(clusterView());
});

const promoteMember = route("post", "/api/v1/cluster/members/{id}/promote", async (ctx) => {
  requireAdmin();
  const node = parseNode(ctx.params.id);
  const body = await ctx.optionalBody();
  for (const key of Object.keys(body)) {
    if (key !== "force" && key !== "replace") throw invalidRequest(`unknown field ${key}`, key);
  }
  if (body.force !== undefined && typeof body.force !== "boolean") throw invalidRequest("force must be true or false", "force");
  let replace: number | null = null;
  if (body.replace !== undefined && body.replace !== null) {
    if (typeof body.replace !== "number" || !Number.isInteger(body.replace) || body.replace < 0) {
      throw invalidRequest("replace must be a member id", "replace");
    }
    replace = body.replace;
  }
  const st = clusterState();
  if (!st.members.has(node)) throw notFound(node);
  const force = body.force === true;
  refuse(promotePreview(clusterView(), node, { force, replace }), force);
  const member = st.members.get(node);
  if (!member) throw notFound(node);
  st.members.set(node, { ...member, role: "voter" });
  if (replace != null) st.members.delete(replace);
  return ok(changed(replace != null ? [node, replace] : [node]));
});

const removeMember = route("delete", "/api/v1/cluster/members/{id}", (ctx) => {
  requireAdmin();
  const node = parseNode(ctx.params.id);
  const st = clusterState();
  if (!st.members.has(node)) throw notFound(node);
  const view = clusterView();
  refuse(removePreview(view, node));
  st.members.delete(node);
  if (st.leader === node) {
    const next = stepDownPreview({ ...view, members: view.members.filter((m) => m.node !== node), leader: null }).successor;
    const successor = next ?? [...st.members.values()].find((m) => m.role === "voter");
    st.leader = successor?.node ?? null;
    st.term += 1;
    if (successor) st.members.set(successor.node, { ...successor, leader: true, lag_entries: null, last_contact_ms: null });
  }
  if (st.node === node && st.leader != null) st.node = st.leader;
  return ok(changed([node]));
});

const stepDown = route("post", "/api/v1/cluster/step-down", () => {
  requireAdmin();
  const st = clusterState();
  const view = clusterView();
  const preview = stepDownPreview(view);
  refuse(preview);
  const next = preview.successor;
  const previous = st.leader;
  if (!next || previous == null) throw clusterProblem("cluster.member.no_successor", 409, BLOCKER_CODES.no_successor[1]);
  const old = st.members.get(previous);
  if (old) st.members.set(previous, { ...old, leader: false, lag_entries: 0, last_contact_ms: 40 });
  st.members.set(next.node, { ...next, leader: true, lag_entries: null, last_contact_ms: null });
  st.leader = next.node;
  st.term += 1;
  commit("cluster", { objects: [nodeRef(previous), nodeRef(next.node)], tables: ["cluster.members"] });
  return ok({ previous, leader: next.node, term: st.term });
});

// ---------------------------------------------------------------------------------
// Digests

/** A deterministic 64-digit hexadecimal digest of `seed` (a stand-in for SHA-256). */
function fakeDigest(seed: string): string {
  let out = "";
  let h = 0x811c9dc5;
  for (let round = 0; out.length < 64; round += 1) {
    for (const ch of `${seed}/${round}`) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
    out += h.toString(16).padStart(8, "0");
  }
  return out.slice(0, 64);
}

const getDigests = route("get", "/api/v1/cluster/digests", (ctx) => {
  requireSession();
  for (const name of ctx.url.searchParams.keys()) {
    if (name !== "revision") {
      throw new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: unknown parameter`, params: { parameter: name } });
    }
  }
  const raw = ctx.query("revision");
  let revision = db.revision;
  if (raw !== null) {
    revision = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
    if (!Number.isSafeInteger(revision)) fail("sys.invalid_query", { params: { name: "revision", value: raw } });
  }
  const st = clusterState();
  const members: MemberDigest[] = [...st.members.values()]
    .sort((a, b) => a.node - b.node)
    .map((m) => ({
      node: m.node,
      sha256: fakeDigest(m.node === st.digestMismatch ? `${revision}/diverged/${m.node}` : String(revision)),
      revision,
      tables: 41,
      entries: 2000 + revision,
    }));
  const report: DigestReport = { revision, agree: st.digestMismatch == null || !st.members.has(st.digestMismatch), members };
  return ok(report);
});

// ---------------------------------------------------------------------------------
// The quorum gate

/** The IPAM collections whose writes the queue accepts, with their item and bulk paths. */
const QUEUEABLE = new RegExp(
  `^/api/v1/(tenants|vrfs|sites|vlans|prefixes|ranges|addresses|hosts)(/bulk|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$`,
  "i",
);

/** Whether the queue accepts a write to `pathname`. */
function queueable(pathname: string): boolean {
  return QUEUEABLE.test(pathname);
}

/** Paths that keep working without a quorum: the queue, sign-in and the event stream. */
function exempt(pathname: string): boolean {
  return (
    pathname === "/api/v1/queue" ||
    pathname.startsWith("/api/v1/queue/") ||
    pathname.startsWith("/api/v1/auth/") ||
    pathname === "/api/v1/events" ||
    pathname.startsWith("/api/v1/events/")
  );
}

/**
 * While the controller is isolated or electing, a write is refused with 503
 * `cluster.no_quorum` before anything else looks at it; reads, dry runs, the queue, sign-in and
 * the event stream pass. A request without a session passes too, so that the session check
 * answers it as it does elsewhere. It must come before every write handler.
 */
const noQuorumGate = http.all("/api/v1/*", ({ request }) => {
  if (!noQuorum()) return undefined;
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return undefined;
  const url = new URL(request.url);
  if (url.searchParams.get("dry_run") === "true" || exempt(url.pathname)) return undefined;
  if (!db.sessions.some((s) => s.id === db.currentSessionId)) return undefined;
  const quorum = clusterState().quorum;
  const params = { since: quorum.since ?? iso(Date.now()), queueable: String(queueable(url.pathname)) };
  const body: ProblemBody = {
    type: "about:blank",
    status: 503,
    code: "cluster.no_quorum",
    title: "No quorum",
    detail: "this controller is not in contact with a quorum; writes are refused",
    params,
  };
  return new Response(JSON.stringify(body), {
    status: 503,
    headers: { "content-type": "application/problem+json", "Retry-After": "5" },
  });
});

/** The quorum gate; the first handler of the happy paths. */
export const quorumGate: HttpHandler[] = [noQuorumGate];

// ---------------------------------------------------------------------------------
// The local queue

const KINDS: Record<string, string> = {
  tenants: "tenant",
  vrfs: "vrf",
  sites: "site",
  vlans: "vlan",
  prefixes: "prefix",
  ranges: "range",
  addresses: "address",
  hosts: "host",
};

function summaryOf(method: WriteMethod, path: string, body: unknown): NonNullable<QueueItem["summary"]> {
  const segments = path.slice(API_PREFIX.length).split("/");
  const collection = segments[0] ?? "";
  const bulk = segments[segments.length - 1] === "bulk";
  const action = bulk ? "bulk" : method === "post" ? "create" : method === "delete" ? "delete" : "update";
  const kind = KINDS[collection] ?? collection.replace(/s$/, "");
  const fields = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  let key: string | undefined;
  for (const name of ["address", "cidr", "fqdn", "name"]) {
    const value = fields[name];
    if (typeof value === "string" && value) {
      key = value;
      break;
    }
  }
  const last = segments[segments.length - 1] ?? "";
  if (key === undefined && !bulk && segments.length > 1 && !isUuid(last)) key = last;
  return key === undefined ? { action, kind } : { action, kind, key };
}

function readRequest(body: Record<string, unknown>): { method: WriteMethod; path: string; query: Record<string, string> | null; payload: unknown; ifMatch: string | null } {
  const method = typeof body.method === "string" ? (body.method.toLowerCase() as WriteMethod) : undefined;
  if (!method || !WRITE_METHODS.includes(method)) throw invalidRequest("method must be post, put, patch or delete", "method");
  if (typeof body.path !== "string" || !body.path.startsWith(API_PREFIX)) {
    throw invalidRequest("path must be an API path below /api/v1/", "path");
  }
  const path = body.path.split("?")[0] ?? body.path;
  let query: Record<string, string> | null = null;
  if (body.query !== undefined && body.query !== null) {
    if (typeof body.query !== "object" || Array.isArray(body.query)) throw invalidRequest("query must be an object of text values", "query");
    query = {};
    for (const [name, value] of Object.entries(body.query)) {
      if (typeof value !== "string") throw invalidRequest("query must be an object of text values", "query");
      query[name] = value;
    }
  }
  const ifMatch = typeof body.if_match === "string" ? body.if_match : null;
  return { method, path, query, payload: body.body, ifMatch };
}

const postQueue = queueRoute("post", "/api/v1/queue", async (ctx) => {
  const { user } = requireSession();
  const request = readRequest((await ctx.body()) as Record<string, unknown>);
  const st = clusterState();
  if (!noQuorum()) {
    throw clusterProblem("queue.not_isolated", 409, "the controller is in contact with a quorum; send the write itself", {
      state: st.quorum.state,
    });
  }
  if (!queueable(request.path)) {
    throw clusterProblem("queue.not_queueable", 422, "the queue takes only writes to IPAM objects", { path: request.path });
  }
  const now = Date.now();
  const item: QueueItem = {
    id: randomId(),
    queued_at: iso(now),
    queued_on: st.node,
    method: request.method,
    path: request.path,
    summary: summaryOf(request.method, request.path, request.payload),
    plan: { changes: [], warnings: [] },
    expires_at: iso(now + QUEUE_LIFETIME_MS),
    state: "queued",
  };
  st.queue.push({ item, author: user.id });
  commit("ipam", { tables: ["ipam.queued_changes"] });
  return created(item);
});

const listQueue = queueRoute("get", "/api/v1/queue", (ctx) => {
  requireSession();
  return ok(paginate(clusterState().queue.map((s) => s.item), ctx.url, db.revision));
});

const cancelQueued = queueRoute("delete", "/api/v1/queue/{id}", (ctx) => {
  requireSession();
  const st = clusterState();
  const index = st.queue.findIndex((s) => s.item.id === ctx.params.id);
  if (index < 0) throw clusterProblem("queue.unknown", 404, "no queued write has this id", { id: ctx.params.id });
  st.queue.splice(index, 1);
  commit("ipam", { tables: ["ipam.queued_changes"] });
  return noContent();
});

/** The queued change of the caller; 404 `queue.unknown` for another person's or an unknown id. */
function ownChange(id: string, userId: string): StoredChange {
  const found = clusterState().changes.find((c) => c.change.id === id && c.author === userId);
  if (!found) throw clusterProblem("queue.unknown", 404, "no queued change of yours has this id", { id });
  return found;
}

function requireConflict(change: QueuedChange): void {
  if (change.state !== "conflict") {
    throw clusterProblem("queue.not_conflict", 409, "the change is not in conflict", { state: change.state });
  }
}

const listConflicts = queueRoute("get", "/api/v1/queue/conflicts", (ctx) => {
  const { user } = requireSession();
  const own = clusterState()
    .changes.filter((c) => c.author === user.id)
    .map((c) => c.change);
  return ok(paginate(own, ctx.url, db.revision));
});

const reapply = queueRoute("post", "/api/v1/queue/conflicts/{id}/reapply", (ctx) => {
  const { user } = requireSession();
  const found = ownChange(ctx.params.id, user.id);
  const change = found.change;
  if (ctx.query("dry_run") === "true") {
    const answer: ReapplyResult = {
      dry_run: true,
      plan: {
        base_revision: db.revision,
        changes: [],
        results: [],
        summary: { counts: [], lines: [], mutations: 0, preconditions: 0, unacknowledged: [], warnings: {} },
        warnings: [],
      },
      warnings: [],
      revision: db.revision,
    };
    return ok(answer);
  }
  requireConflict(change);
  const expected = ctx.ifMatch();
  if (typeof expected === "number" && expected !== change.revision) fail("sys.store.precondition_failed");
  change.state = "reapplied";
  change.conflict = null;
  change.job_id = randomId();
  change.resolved_at = iso(Date.now());
  commit("ipam", { tables: ["ipam.queued_changes"] }, [change]);
  const answer: ReapplyResult = { dry_run: false, warnings: [], job_id: change.job_id, revision: change.revision };
  return ok(answer);
});

const discard = queueRoute("delete", "/api/v1/queue/conflicts/{id}", (ctx) => {
  const { user } = requireSession();
  const change = ownChange(ctx.params.id, user.id).change;
  requireConflict(change);
  change.state = "discarded";
  change.resolved_at = iso(Date.now());
  commit("ipam", { tables: ["ipam.queued_changes"] }, [change]);
  return noContent();
});

export const clusterRoutes: HttpHandler[] = [
  listMembers,
  promoteMember,
  removeMember,
  stepDown,
  getDigests,
  postQueue,
  listQueue,
  // `/queue/conflicts` before `/queue/:id`.
  listConflicts,
  reapply,
  discard,
  cancelQueued,
];
