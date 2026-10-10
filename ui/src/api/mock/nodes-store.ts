// The cluster nodes and enrolment tokens of the mock (docs/cluster.md): two enrolled probes,
// one connected and current, one disconnected after its handshake was refused for want of a
// common protocol major and with a certificate close to renewal; and one pending enrolment
// token. Everything uses the documentation ranges. The state is built when it is first read
// and again after every reset; the setup scenarios have no nodes.
import type { components } from "../generated/schema";
import { db, onMockReset } from "./db";
import { MOCK_USER_IDS, MOCK_VERSION } from "./fixtures";
import { IPAM_IDS } from "./ipam/api";
import { DAY_MS, HOUR_MS, MINUTE, iso, randomHex } from "./util";

type S = components["schemas"];
export type NodeView = S["NodeView"];
export type EnrolmentView = S["EnrolmentView"];
export type ClusterStatus = S["ClusterStatus"];

/** The protocol majors the mock controller implements. */
export const CONTROLLER_MAJORS: readonly number[] = [1];

/** The first id an enrolled node gets (ids are never reused). */
export const FIRST_NODE_ID = 1001;

/** The lifetime of a node certificate. */
export const CERT_LIFETIME_MS = 365 * DAY_MS;

/** Used and expired tokens stay listed this long. */
export const KEEP_TOKENS_MS = 7 * DAY_MS;

/** The status warning of nodes that share no protocol major with the controller. */
export const MISMATCH_WARNING = "cluster.protocol.mismatch";

/** The fixed ids of the seed. */
export const NODE_IDS = {
  dmz: 1001,
  lab: 1002,
  /** The pending enrolment token. */
  token: "0190d1c2-0000-7000-8000-00000f000001",
} as const;

/** An enrolment token as the mock keeps it: the view and the secret part of the token text. */
export interface StoredEnrolment {
  view: Omit<EnrolmentView, "state">;
  secret: string;
}

export interface NodesState {
  nodes: Map<number, NodeView>;
  enrolments: Map<string, StoredEnrolment>;
  /** The last id handed out. */
  lastId: number;
  /** Revoked certificate serials with the node they belonged to. */
  revoked: Map<string, number>;
  /** Addresses the cluster port listens on; opened by the first token. */
  listening: string[];
}

let state: NodesState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built from the seed on first use after a reset. */
export function nodesState(): NodesState {
  if (!state) {
    const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
    state = empty
      ? { nodes: new Map(), enrolments: new Map(), lastId: FIRST_NODE_ID - 1, revoked: new Map(), listening: [] }
      : buildSeed(Date.now(), db.revision);
  }
  return state;
}

/** The object reference of a node in events and audit records (`Uuid::from_u64_pair(0, id)`). */
export function nodeRef(id: number): { kind: "node"; id: string } {
  return { kind: "node", id: `00000000-0000-0000-0000-${id.toString(16).padStart(12, "0")}` };
}

/** A certificate reference with a fresh serial and digest. */
export function certificate(notBefore: number): S["CertificateRef"] {
  return {
    serial: randomHex(16),
    sha256: randomHex(32),
    not_before: iso(notBefore),
    not_after: iso(notBefore + CERT_LIFETIME_MS),
  };
}

/** The state of a token at `now`. */
export function enrolmentState(view: Omit<EnrolmentView, "state">, now = Date.now()): S["EnrolmentState"] {
  if (view.used) return "used";
  return Date.parse(view.expires_at) <= now ? "expired" : "pending";
}

/** The tokens to list at `now`: newest first, without used and expired ones older than a week. */
export function enrolmentList(now = Date.now()): EnrolmentView[] {
  return [...nodesState().enrolments.values()]
    .map(({ view }) => ({ ...view, state: enrolmentState(view, now) }))
    .filter((view) => {
      if (view.state === "pending") return true;
      const ended = view.used ? Date.parse(view.used.at) : Date.parse(view.expires_at);
      return now - ended < KEEP_TOKENS_MS;
    })
    .sort((a, b) => (a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0));
}

/** The `cluster` member of `GET /system/status`. */
export function clusterStatus(): ClusterStatus {
  const nodes = [...nodesState().nodes.values()];
  const versions: Record<string, number> = {};
  for (const node of nodes) {
    if (!node.connected) continue;
    const version = node.connection?.version || node.version || "unknown";
    versions[version] = (versions[version] ?? 0) + 1;
  }
  return {
    listening: [...nodesState().listening],
    majors: [...CONTROLLER_MAJORS],
    nodes: nodes.length,
    connected: nodes.filter((n) => n.connected).length,
    versions,
    mismatched: nodes.filter((n) => n.protocol.mismatch).length,
  };
}

/** The status warning of the nodes with a refused handshake, when there are any. */
export function clusterWarnings(): S["StatusWarning"][] {
  const mismatched = [...nodesState().nodes.values()].filter((n) => n.protocol.mismatch);
  if (mismatched.length === 0) return [];
  const detail = mismatched
    .map((n) => `${n.name} (node ${n.id}) offers protocol major(s) ${(n.protocol.mismatch?.theirs ?? []).join(", ")}`)
    .join("; ");
  return [
    {
      code: MISMATCH_WARNING,
      detail: `nodes share no protocol major with this controller, which implements ${CONTROLLER_MAJORS.join(", ")}: ${detail}; upgrade the older side`,
      params: { count: String(mismatched.length), nodes: mismatched.map((n) => String(n.id)).join(",") },
    },
  ];
}

function buildSeed(now: number, revision: number): NodesState {
  const vrf = IPAM_IDS.vrf.default;
  const dmzCert = certificate(now - 40 * DAY_MS);
  const labCert = certificate(now - 345 * DAY_MS);
  const dmz: NodeView = {
    id: NODE_IDS.dmz,
    name: "probe-dmz",
    roles: ["probe"],
    address: "192.0.2.20",
    vrf,
    certificate: dmzCert,
    enrolled_at: iso(now - 40 * DAY_MS),
    enrolled_by: MOCK_USER_IDS.alex,
    renewed_at: null,
    last_seen: iso(now - 4000),
    version: MOCK_VERSION,
    protocol: { offered: [1], agreed: 1, mismatch: null },
    connected: true,
    connection: {
      since: iso(now - 3 * HOUR_MS),
      peer: "192.0.2.20:51234",
      major: 1,
      version: MOCK_VERSION,
      last_beat: iso(now - 4000),
      buffered_batches: 0,
      buffered_bytes: 0,
      dropped_batches: 0,
      certificate_not_after: dmzCert.not_after,
    },
    revision,
  };
  const lab: NodeView = {
    id: NODE_IDS.lab,
    name: "probe-lab",
    roles: ["probe"],
    address: "203.0.113.20",
    vrf,
    certificate: labCert,
    enrolled_at: iso(now - 345 * DAY_MS),
    enrolled_by: MOCK_USER_IDS.alex,
    renewed_at: null,
    last_seen: iso(now - 2 * DAY_MS),
    version: "0.2.0",
    protocol: { offered: [2], agreed: 1, mismatch: { ours: [1], theirs: [2], at: iso(now - HOUR_MS), version: "0.2.0" } },
    connected: false,
    connection: null,
    revision,
  };
  const token: StoredEnrolment = {
    view: {
      id: NODE_IDS.token,
      name: "probe-garage",
      roles: ["probe"],
      vrf,
      created_by: MOCK_USER_IDS.alex,
      created_at: iso(now - 10 * MINUTE),
      expires_at: iso(now + 50 * MINUTE),
      used: null,
      revision,
    },
    secret: "Z2FyYWdlLXByb2JlLXRva2VuLW9mLXRoZS1tb2NrLTA",
  };
  return {
    nodes: new Map([
      [dmz.id, dmz],
      [lab.id, lab],
    ]),
    enrolments: new Map([[token.view.id, token]]),
    lastId: NODE_IDS.lab,
    revoked: new Map(),
    listening: ["0.0.0.0:8444"],
  };
}
