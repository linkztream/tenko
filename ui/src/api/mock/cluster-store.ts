// The controller cluster and the local write queue of the mock (OPS-03, OPS-26, WP3.9): four
// members behind controller 1 (a leader, two caught-up voters and a learner that is still
// catching up), the quorum state of the answering controller, the queue of writes it holds
// while it is isolated and what became of them after the heal. The setup scenarios have one
// member and no quorum to lose. The state is built when it is first read and again after every
// reset. `mockCluster` moves the quorum from the dev console (`window.tenkoMockCluster`) and
// from tests.
import type { ClusterView, DataFormatStatus, MemberView, QuorumKind, QuorumView, QueuedChangeView, QueuedRequest, QueueItemView } from "../../cluster/model";
import type { PlanView, SystemStatus } from "../types";
import { commit, db, onMockReset, recordAlarm } from "./db";
import { MOCK_USER_IDS, MOCK_VERSION } from "./fixtures";
import { currentPrincipal } from "./auth";
import { DAY_MS, iso, randomId } from "./util";

/** The data format the mock binaries know. */
export const MOCK_DATA_FORMAT = 3;

/** What every mock binary reports of its compatibility (docs/upgrades.md, section 3). */
const compat = () => ({ protocol_majors: [1, 2], raft_wire: "openraft-0.9/cbor-1", formats: [2, 3] });

type StatusWarning = SystemStatus["warnings"][number];

/** The controller that answers. */
export const ANSWERING_NODE = 1;

/** Queued items live this long before they expire. */
export const QUEUE_LIFETIME_MS = 7 * DAY_MS;

/** The fixed ids of the seed. */
export const CLUSTER_IDS = {
  leader: 1,
  voterA: 1101,
  voterB: 1102,
  learner: 1103,
  /** The address of the conflict seeded when a heal finds an empty queue. */
  address: "0190d1c2-0000-7000-8000-00000c100001",
} as const;

/** A queued item with the user who queued it and the request (the wire shape names neither). */
export interface StoredItem {
  item: QueueItemView;
  author: string;
  request: QueuedRequest;
}

/** A queued change after the heal, with its author. */
export interface StoredChange {
  change: QueuedChangeView;
  author: string;
}

/** A plan without changes: the mock plans queued changes against nothing. */
export function emptyPlan(): PlanView {
  return {
    base_revision: db.revision,
    changes: [],
    results: [],
    summary: { counts: [], lines: [], mutations: 0, preconditions: 0, unacknowledged: [], warnings: {} },
    warnings: [],
  };
}

/** The conflict of a change whose plan after the heal differs from the queued plan. */
const PLAN_CHANGED = { code: "queue.plan_changed", status: 409, detail: "the plan after the heal differs from the queued plan", params: {} };
/** The conflict of a change that expired before the heal. */
const EXPIRED = { code: "queue.expired", status: 409, detail: "the change expired before the heal", params: {} };

/** The record of a settled change as the drain writes it. */
function settled(item: QueueItemView, request: QueuedRequest, author: string, at: string): QueuedChangeView {
  return {
    id: item.id,
    author,
    principal: { kind: "user", id: author, session: "mock-session", strength: "password" },
    commands: [],
    queued_at: item.queued_at,
    queued_on: item.queued_on,
    queued_plan: item.plan,
    request,
    settled_at: at,
    state: "applied",
    summary: item.summary,
    revision: db.revision,
  };
}

export interface ClusterState {
  term: number;
  quorum: QuorumView;
  changing: boolean;
  /** The controller that answers. */
  node: number;
  leader: number | null;
  members: Map<number, MemberView>;
  queue: StoredItem[];
  changes: StoredChange[];
  /** The member that reports another digest, if any. */
  digestMismatch: number | null;
  /** A format migration waits for the voter that runs an older binary. */
  migrationPending: boolean;
}

let state: ClusterState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built from the seed on first use after a reset. */
export function clusterState(): ClusterState {
  if (!state) state = buildSeed(Date.now());
  return state;
}

/** The cluster as the answering controller sees it; the replication figures are as of now. */
export function clusterView(): ClusterView {
  const st = clusterState();
  const members = [...st.members.values()]
    .sort((a, b) => a.node - b.node)
    .map((m) => ({ ...m, matched: m.leader ? db.revision : m.lag_entries == null ? null : Math.max(0, db.revision - m.lag_entries) }));
  return {
    node: st.node,
    term: st.term,
    quorum: { ...st.quorum },
    changing: st.changing,
    leader: st.leader,
    members,
  };
}

/** The quorum is lost: writes are refused or queued. */
export function noQuorum(): boolean {
  const kind = clusterState().quorum.state;
  return kind === "isolated" || kind === "electing";
}

/** The seed: the cluster of four, or the one member of a fresh installation. */
function buildSeed(now: number): ClusterState {
  const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  const joined = iso(now - 5 * DAY_MS);
  const leader: MemberView = {
    node: CLUSTER_IDS.leader,
    name: "ctl-1.example.test",
    address: "192.0.2.11:8444",
    role: "voter",
    leader: true,
    version: MOCK_VERSION,
    data_format: MOCK_DATA_FORMAT,
    ...compat(),
    joined_at: joined,
    matched: db.revision,
    lag_entries: null,
    last_contact_ms: null,
  };
  const members = new Map<number, MemberView>([[leader.node, leader]]);
  if (!empty) {
    const follower = (node: number, name: string, address: string, role: MemberView["role"], lag: number, contact: number): MemberView => ({
      node,
      name,
      address,
      role,
      leader: false,
      version: MOCK_VERSION,
      data_format: MOCK_DATA_FORMAT,
      ...compat(),
      joined_at: iso(now - (role === "voter" ? 4 : 1) * DAY_MS),
      matched: Math.max(0, db.revision - lag),
      lag_entries: lag,
      last_contact_ms: contact,
    });
    for (const m of [
      follower(CLUSTER_IDS.voterA, "ctl-2.example.test", "192.0.2.12:8444", "voter", 0, 40),
      follower(CLUSTER_IDS.voterB, "ctl-3.example.test", "192.0.2.13:8444", "voter", 2, 60),
      follower(CLUSTER_IDS.learner, "ctl-4.example.test", "198.51.100.14:8444", "learner", 4200, 300),
    ]) {
      members.set(m.node, m);
    }
  }
  return {
    term: 7,
    quorum: { state: empty ? "single" : "healthy" },
    changing: false,
    node: ANSWERING_NODE,
    leader: ANSWERING_NODE,
    members,
    queue: [],
    changes: [],
    digestMismatch: null,
    migrationPending: false,
  };
}

// ---------------------------------------------------------------------------------
// Controls

/** The user the next seeded conflict belongs to: the signed-in one. */
function currentUserId(): string {
  try {
    return currentPrincipal()?.user.id ?? MOCK_USER_IDS.alex;
  } catch {
    return MOCK_USER_IDS.alex;
  }
}

function announce(quorum: QuorumView): void {
  const params: Record<string, string> = { state: quorum.state };
  if (quorum.since) params.since = quorum.since;
  if (quorum.last_contact) params.last_contact = quorum.last_contact;
  if (quorum.applied != null) params.applied = String(quorum.applied);
  recordAlarm("cluster", { kind: "cluster.quorum", params });
}

/** Moves the quorum to `kind` and tells the open streams. */
function setQuorum(kind: QuorumKind): void {
  const now = iso(Date.now());
  const quorum: QuorumView = { state: kind };
  if (kind === "isolated") {
    quorum.since = now;
    quorum.last_contact = now;
    quorum.applied = db.revision;
  } else if (kind === "electing") {
    quorum.since = now;
  }
  clusterState().quorum = quorum;
  announce(quorum);
}

/**
 * The partition heals: the quorum is back and the queue drains. With `conflicts` the first
 * item applies and the others conflict; an expired item becomes an expired record; an empty
 * queue gets one conflict so the views have something to show.
 */
function heal(options: { conflicts: boolean }): void {
  setQuorum("healthy");
  const st = clusterState();
  const now = iso(Date.now());
  const drained: StoredChange[] = st.queue.map(({ item, author, request }, index) => {
    const change = settled(item, request, author, now);
    if (item.state === "expired") {
      change.state = "expired";
      change.conflict = EXPIRED;
    } else if (options.conflicts && index > 0) {
      change.state = "conflict";
      change.conflict = PLAN_CHANGED;
      change.current_plan = emptyPlan();
    }
    return { change, author };
  });
  if (options.conflicts && drained.length === 0) {
    const author = currentUserId();
    const path = `/addresses/${CLUSTER_IDS.address}`;
    const item: QueueItemView = {
      id: randomId(),
      queued_at: iso(Date.now() - 20 * 60_000),
      queued_on: st.node,
      method: "PATCH",
      path,
      plan: emptyPlan(),
      summary: { action: "update", kind: "address", key: "192.0.2.50" },
      expires_at: iso(Date.now() + QUEUE_LIFETIME_MS),
      state: "queued",
    };
    const change = settled(item, { method: "PATCH", path, body: { address: "192.0.2.50" } as unknown as QueuedRequest["body"] }, author, now);
    change.state = "conflict";
    change.conflict = PLAN_CHANGED;
    drained.push({ author, change });
  }
  st.queue = [];
  st.changes.push(...drained);
  const touched = drained.map((d) => d.change);
  commit("ipam", { tables: ["ipam.queued_changes"] }, touched);
}

/** Makes `node` report another state digest (null: every member agrees). */
function setDigestMismatch(node: number | null): void {
  clusterState().digestMismatch = node;
}

/** Plays a migration that waits for the last voter (true) or the finished one (false). */
function setMigrationPending(pending: boolean): void {
  const st = clusterState();
  st.migrationPending = pending;
  const voter = st.members.get(CLUSTER_IDS.voterB);
  if (voter) {
    voter.data_format = pending ? MOCK_DATA_FORMAT - 1 : MOCK_DATA_FORMAT;
    voter.formats = pending ? [1, 2] : [2, 3];
  }
}

/** The `data_format` member of `GET /system/status`. */
export function dataFormatStatus(): DataFormatStatus {
  const st = clusterState();
  if (!st.migrationPending) return { stored: MOCK_DATA_FORMAT, binary: MOCK_DATA_FORMAT };
  return {
    stored: MOCK_DATA_FORMAT - 1,
    binary: MOCK_DATA_FORMAT,
    pending: { target: MOCK_DATA_FORMAT, blocked_by: [{ node: CLUSTER_IDS.voterB, data_format: MOCK_DATA_FORMAT - 1 }] },
  };
}

/** The warning that goes with a pending migration. */
export function dataFormatWarnings(): StatusWarning[] {
  const format = dataFormatStatus();
  if (!format.pending || format.pending.blocked_by.length === 0) return [];
  const nodes = format.pending.blocked_by.map((b) => String(b.node)).join(", ");
  return [
    {
      code: "upgrade.migration_blocked",
      detail: `the data stays in format ${format.stored} until every voter runs a binary that knows format ${format.pending.target}; upgrade controller(s) ${nodes}`,
      params: { stored: String(format.stored), target: String(format.pending.target), nodes },
    },
  ];
}

/** What the dev console and the tests use to play a partition. */
export interface MockCluster {
  setMigrationPending(pending: boolean): void;
  setQuorum(state: QuorumKind): void;
  heal(options: { conflicts: boolean }): void;
  setDigestMismatch(node: number | null): void;
}

export const mockCluster: MockCluster = { setQuorum, heal, setDigestMismatch, setMigrationPending };

declare global {
  interface Window {
    tenkoMockCluster?: MockCluster;
  }
}

if (typeof window !== "undefined") window.tenkoMockCluster = mockCluster;
