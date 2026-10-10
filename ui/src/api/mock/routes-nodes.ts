// Cluster nodes and enrolment tokens of the mock API (docs/cluster.md, sections 1, 3 and 9):
// the node list by id with the live connection, one node with its `ETag`, revocation, the
// enrolment tokens (created once with the token text and the command to run on the node,
// listed without it, withdrawn whatever their state) and the public enrolment itself.
//
// Simplifications: a certificate request is accepted when it is a PEM block of the right
// type; certificates are placeholders; the serials of a revoked node are kept until a reset;
// a token expires by its own `expires_at` only.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { appendAudit } from "./audit-store";
import { requireAdmin, requireSession } from "./auth";
import { db, recordEvent } from "./db";
import { MOCK_CA_FINGERPRINT, MOCK_VERSION } from "./fixtures";
import {
  CONTROLLER_MAJORS,
  certificate,
  enrolmentList,
  enrolmentState,
  nodeRef,
  nodesState,
  type EnrolmentView,
  type NodeView,
} from "./nodes-store";
import { Problem, created, noContent, ok } from "./reply";
import { paginate, route } from "./route";
import { MOCK_CA_ROOT_PEM } from "./routes-system";
import { b64url, iso, isUuid, randomBytes, randomId } from "./util";

type S = components["schemas"];

/** The roles a token may name. A controller joins differently (Slice 3). */
const NODE_ROLES = ["probe", "dns", "dhcp"] as const;
const NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const MIN_LIFETIME = 60;
const MAX_LIFETIME = 604_800;
const DEFAULT_LIFETIME = 3_600;
const NO_STORE = { "Cache-Control": "no-store" };
/** The singleton reference of the node registry (token records name no node). */
const REGISTRY = { kind: "node", id: "00000000-0000-0000-0000-000000000000" } as const;

function invalidRequest(detail: string, field?: string): Problem {
  return new Problem("sys.invalid_request", { status: 400, detail, params: field ? { field } : {} });
}

function parseNodeId(raw: string): number {
  const id = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(id) || id <= 0) throw invalidRequest("the node identifier is not a positive number", "id");
  return id;
}

function findNode(id: number): NodeView {
  const node = nodesState().nodes.get(id);
  if (!node) {
    throw new Problem("cluster.node.not_found", { status: 404, detail: `no enrolled node has the id ${id}`, params: { id: String(id) } });
  }
  return node;
}

function nameTaken(name: string): boolean {
  const lower = name.toLowerCase();
  return [...nodesState().nodes.values()].some((n) => n.name.toLowerCase() === lower);
}

function checkName(name: string): void {
  if (!NAME_RULE.test(name)) {
    throw new Problem("cluster.node.name", {
      status: 422,
      detail: "a node name has 1 to 63 letters, digits, dots, hyphens and underscores and starts with a letter or digit",
      params: { name },
    });
  }
  if (nameTaken(name)) {
    throw new Problem("cluster.node.name_taken", { status: 409, detail: `another node is called ${name}`, params: { name } });
  }
}

/** The roles of a request: known node roles, never `controller`. */
function readRoles(raw: unknown, fallback: readonly string[], refusal: number): string[] {
  if (raw === undefined || raw === null) return [...fallback];
  if (!Array.isArray(raw) || raw.some((r) => typeof r !== "string")) throw invalidRequest("roles must be a list of role names", "roles");
  const roles = [...new Set(raw as string[])];
  if (roles.length === 0) return [...fallback];
  for (const role of roles) {
    if (role === "controller") {
      throw new Problem("cluster.enrolment.roles", { status: refusal, detail: "a controller does not enrol with a token yet", params: { role } });
    }
    if (!(NODE_ROLES as readonly string[]).includes(role)) throw invalidRequest(`unknown role ${role}`, "roles");
  }
  return roles;
}

/** Records a change of the `cluster` tables; returns its revision. */
function clusterEvent(change: { objects?: { kind: string; id: string }[]; deleted?: { kind: string; id: string }[]; tables: string[] }): number {
  return recordEvent("cluster", { objects: change.objects ?? [], deleted: change.deleted ?? [], tables: change.tables }).id ?? db.revision;
}

// ---------------------------------------------------------------------------------
// Nodes

const listNodes = route("get", "/api/v1/nodes", (ctx) => {
  requireSession();
  for (const name of ctx.url.searchParams.keys()) {
    if (!["limit", "cursor", "at_least"].includes(name)) {
      throw new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: unknown parameter`, params: { parameter: name } });
    }
  }
  const nodes = [...nodesState().nodes.values()].sort((a, b) => a.id - b.id);
  return ok(paginate(nodes, ctx.url, db.revision));
});

const getNode = route("get", "/api/v1/nodes/{id}", (ctx) => {
  requireSession();
  const node = findNode(parseNodeId(ctx.params.id));
  return ok(node, { ETag: `"${node.revision}"` });
});

const revokeNode = route("delete", "/api/v1/nodes/{id}", (ctx) => {
  requireAdmin();
  const node = findNode(parseNodeId(ctx.params.id));
  const st = nodesState();
  st.nodes.delete(node.id);
  st.revoked.set(node.certificate.serial, node.id);
  clusterEvent({ deleted: [nodeRef(node.id)], tables: ["cluster.nodes", "cluster.node_names", "cluster.revocations"] });
  appendAudit({ action: "cluster.node.revoke", objects: [nodeRef(node.id)], context: { serials: node.certificate.serial } });
  return noContent();
});

// ---------------------------------------------------------------------------------
// Enrolment tokens

const listEnrolments = route("get", "/api/v1/nodes/enrolments", () => {
  requireAdmin();
  return ok({ items: enrolmentList() });
});

const createEnrolment = route("post", "/api/v1/nodes/enrolments", async (ctx) => {
  const { user } = requireAdmin();
  const body = await ctx.optionalBody();
  for (const key of Object.keys(body)) {
    if (!["roles", "name", "vrf", "expires_in_secs"].includes(key)) throw invalidRequest(`unknown field ${key}`, key);
  }
  const roles = readRoles(body.roles, ["probe"], 422);
  let name: string | null = null;
  if (body.name !== undefined && body.name !== null) {
    if (typeof body.name !== "string") throw invalidRequest("name must be text", "name");
    name = body.name.trim();
    checkName(name);
  }
  let vrf: string | null = null;
  if (body.vrf !== undefined && body.vrf !== null) {
    if (typeof body.vrf !== "string" || !isUuid(body.vrf)) throw invalidRequest("vrf must be a VRF identifier", "vrf");
    vrf = body.vrf;
  }
  let lifetime = DEFAULT_LIFETIME;
  if (body.expires_in_secs !== undefined && body.expires_in_secs !== null) {
    if (typeof body.expires_in_secs !== "number" || !Number.isInteger(body.expires_in_secs)) {
      throw invalidRequest("expires_in_secs must be a whole number", "expires_in_secs");
    }
    lifetime = body.expires_in_secs;
    if (lifetime < MIN_LIFETIME || lifetime > MAX_LIFETIME) {
      throw new Problem("cluster.enrolment.lifetime", {
        status: 422,
        detail: `a token lives 60 to 604800 seconds, not ${lifetime}`,
        params: { min: String(MIN_LIFETIME), max: String(MAX_LIFETIME), value: String(lifetime) },
      });
    }
  }
  const now = Date.now();
  const id = randomId();
  const secret = b64url(randomBytes(32));
  const st = nodesState();
  // Creating a token opens the cluster port when it starts on demand.
  if (st.listening.length === 0) st.listening = ["0.0.0.0:8444"];
  const revision = clusterEvent({ tables: ["cluster.enrolments"] });
  const view: Omit<EnrolmentView, "state"> = {
    id,
    name,
    roles,
    vrf,
    created_by: user.id,
    created_at: iso(now),
    expires_at: iso(now + lifetime * 1000),
    used: null,
    revision,
  };
  st.enrolments.set(id, { view, secret });
  appendAudit({
    action: "cluster.enrolment.create",
    objects: [REGISTRY],
    context: { enrolment: id, roles: roles.join(","), expires_at: view.expires_at },
  });
  const token = `tnk1.${id.replace(/-/g, "")}.${secret}`;
  const answer: S["CreatedEnrolment"] = {
    enrolment: { ...view, state: "pending" },
    token,
    ca_fingerprint: MOCK_CA_FINGERPRINT,
    command: `tenko node enrol --controller ${ctx.url.origin} --token ${token} --ca-fingerprint ${MOCK_CA_FINGERPRINT}`,
  };
  return created(answer, NO_STORE);
});

const deleteEnrolment = route("delete", "/api/v1/nodes/enrolments/{id}", (ctx) => {
  requireAdmin();
  const id = ctx.params.id;
  if (!isUuid(id)) throw invalidRequest("the enrolment identifier is not a UUID", "id");
  const st = nodesState();
  const found = st.enrolments.get(id);
  if (!found) {
    throw new Problem("cluster.enrolment.not_found", { status: 404, detail: `no enrolment token has the id ${id}`, params: { id } });
  }
  st.enrolments.delete(id);
  clusterEvent({ tables: ["cluster.enrolments"] });
  appendAudit({ action: "cluster.enrolment.delete", objects: [REGISTRY], context: { enrolment: id, state: enrolmentState(found.view) } });
  return noContent();
});

// ---------------------------------------------------------------------------------
// Enrolment (public: the token is the credential)

/** `tnk1.<32 hex>.<43 base64url>` as the id of its record and the secret. */
function parseToken(text: string): { id: string; secret: string } | null {
  const match = /^tnk1\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/.exec(text.trim());
  if (!match) return null;
  const hex = match[1] ?? "";
  const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  return { id, secret: match[2] ?? "" };
}

const enrol = route("post", "/api/v1/nodes/enrol", async (ctx) => {
  const body = await ctx.body();
  if (typeof body.token !== "string" || typeof body.csr !== "string") throw invalidRequest("token and csr are required");
  const st = nodesState();
  const parsed = parseToken(body.token);
  const stored = parsed ? st.enrolments.get(parsed.id) : undefined;
  if (!parsed || !stored || stored.secret !== parsed.secret) {
    throw new Problem("cluster.enrolment.invalid_token", { status: 401, detail: "the token is malformed, unknown or has a wrong secret" });
  }
  const now = Date.now();
  const tokenState = enrolmentState(stored.view, now);
  if (tokenState === "used") throw new Problem("cluster.enrolment.used", { status: 401, detail: "the token was used already" });
  if (tokenState === "expired") throw new Problem("cluster.enrolment.expired", { status: 401, detail: "the token expired" });
  const roles = readRoles(body.roles, stored.view.roles, 403);
  if (roles.some((r) => !stored.view.roles.includes(r))) {
    throw new Problem("cluster.enrolment.roles", { status: 403, detail: "the token does not allow a requested role" });
  }
  const majors = Array.isArray(body.majors) ? (body.majors as unknown[]).filter((m): m is number => typeof m === "number") : [1];
  if (!majors.some((m) => CONTROLLER_MAJORS.includes(m))) {
    throw new Problem("cluster.protocol.unsupported", { status: 409, detail: "the node and the controller share no protocol major" });
  }
  const asked = typeof body.name === "string" && body.name.trim() ? body.name.trim() : null;
  const name = stored.view.name ?? asked ?? `node-${st.lastId + 1}`;
  checkName(name);
  const address = typeof body.address === "string" && body.address.trim() ? body.address.trim() : "192.0.2.250";
  if (/\s/.test(address) || address.length > 253) {
    throw new Problem("cluster.node.address", { status: 422, detail: "the address is neither an IP address nor a host name", params: { address } });
  }
  if (!body.csr.includes("-----BEGIN CERTIFICATE REQUEST-----")) {
    throw new Problem("cluster.ca.invalid_csr", { status: 422, detail: "the certificate request is unusable" });
  }
  const nodeId = st.lastId + 1;
  st.lastId = nodeId;
  const revision = clusterEvent({ objects: [nodeRef(nodeId)], tables: ["cluster.nodes", "cluster.node_names", "cluster.enrolments"] });
  const node: NodeView = {
    id: nodeId,
    name,
    roles,
    address,
    vrf: stored.view.vrf ?? null,
    certificate: certificate(now),
    enrolled_at: iso(now),
    enrolled_by: stored.view.created_by ?? null,
    renewed_at: null,
    last_seen: null,
    version: typeof body.version === "string" && body.version ? body.version : MOCK_VERSION,
    protocol: { offered: majors, agreed: null, mismatch: null },
    connected: false,
    connection: null,
    revision,
  };
  st.nodes.set(nodeId, node);
  stored.view = { ...stored.view, used: { node: nodeId, at: iso(now) }, revision };
  appendAudit({
    action: "cluster.node.enrol",
    objects: [nodeRef(nodeId)],
    principal: { kind: "system", component: "cluster" } as S["Principal"],
    context: { enrolment: parsed.id },
  });
  const answer: S["EnrolResponse"] = {
    node,
    certificate: MOCK_CA_ROOT_PEM,
    ca_root: MOCK_CA_ROOT_PEM,
    endpoints: [],
    cluster_port: 8444,
    heartbeat_secs: 10,
    majors: [...CONTROLLER_MAJORS],
  };
  return created(answer, NO_STORE);
});

export const nodeRoutes: HttpHandler[] = [listNodes, listEnrolments, createEnrolment, deleteEnrolment, enrol, getNode, revokeNode];
