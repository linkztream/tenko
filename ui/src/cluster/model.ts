// The controller cluster in the UI (OPS-03, OPS-26): the wire shapes of `/cluster/*` and
// `/queue*` in one place, so a change of the server's DTOs is one edit here, and the rules the
// cluster page and the partition views follow (role and health words, the previews of a
// promotion, a removal and a step-down, the digest comparison).
//
// The shapes are the generated ones of the OpenAPI document: the cluster of WP3.1a and the
// queue of WP3.9.
import type { components } from "../api/generated/schema";
import type { WriteResponse } from "../api/types";
import { formatDuration, formatNumber, t } from "../i18n";

// ---------------------------------------------------------------------------------
// Wire shapes: the cluster (WP3.1a, generated from the OpenAPI document)

type S = components["schemas"];

/** `single` (one voter, never isolated), `healthy`, `electing` or `isolated`. */
export type QuorumKind = S["QuorumKind"];
export const QUORUM_KINDS: readonly QuorumKind[] = ["single", "healthy", "electing", "isolated"];
/** Whether a controller is in contact with a quorum (OPS-26). */
export type QuorumView = S["QuorumView"];
export type MemberRole = S["MemberRole"];
/** One member of the controller cluster. Replication figures come from the leader. */
export type MemberView = S["MemberView"];
/** `GET /cluster/members` and the answer of a membership change. */
export type ClusterView = S["ClusterView"];
/** Body of `POST /cluster/members/{id}/promote`. */
export type PromoteRequest = S["PromoteRequest"];
/** Answer of `POST /cluster/step-down`. */
export type StepDown = S["StepDown"];
export type MemberDigest = S["MemberDigest"];
/** `GET /cluster/digests`. */
export type DigestReport = S["DigestReport"];

// ---------------------------------------------------------------------------------
// Wire shapes: queued changes (WP3.9, generated from the OpenAPI document)

/** Body of `POST /queue` as the document spells it; its `body` is any JSON. */
export type QueuedRequest = S["QueuedRequest"];
/** The refused write as the person sent it, with the JSON body of the request as it is. */
export type QueueRequest = Omit<QueuedRequest, "body"> & { body?: unknown };
/** What a queued change does, for its line in the lists. */
export type ChangeSummary = S["ChangeSummary"];
/** `create`, `update`, `delete`, `restore` or `bulk`. */
export type SummaryAction = S["SummaryAction"];
/** `queued` (waits for the heal), `applying` (the heal applies it) or `expired`. */
export type ItemState = S["ItemState"];
export const ITEM_STATES: readonly ItemState[] = ["queued", "applying", "expired"];
/** An item of the local queue of an isolated controller (`GET /queue`, the answer of `POST /queue`). */
export type QueueItemView = S["QueueItemView"];
/** `GET /queue`: the caller's items on this controller, oldest first. */
export type QueueList = S["QueueList"];
/** What became of a queued change after the heal: `applied`, `conflict` or `expired`. */
export type ChangeState = S["ChangeState"];
export const CHANGE_STATES: readonly ChangeState[] = ["applied", "conflict", "expired"];
/** Why a queued change did not apply by itself (`queue.plan_changed`, a planner or authorization error). */
export type Conflict = S["Conflict"];
/** One settled queued change of the caller, with the revision of its record (`GET /queue/conflicts`). */
export type QueuedChangeView = S["QueuedChangeView"];
/** `GET /queue/conflicts`. */
export type QueuedChangeList = S["QueuedChangeList"];

/**
 * The answer of a re-apply: the document leaves it open because it is the answer of the endpoint
 * the change re-applies (`WriteResponse` of the object, or `BulkResponse`). The members the views
 * read are the ones both have.
 */
export type ReapplyResult = Pick<WriteResponse<unknown>, "dry_run" | "plan" | "warnings" | "job_id" | "revision">;

/** Whether a settled change waits for the person: a conflict, or a change that expired before the heal. */
export function needsDecision(change: Pick<QueuedChangeView, "state">): boolean {
  return change.state !== "applied";
}

// ---------------------------------------------------------------------------------
// Rules

/** A learner within this many entries of the leader counts as caught up (`promote_lag_entries`). */
export const PROMOTE_LAG_ENTRIES = 100;
/** A member the leader has not heard from for this long is out of contact. */
export const CONTACT_LOST_MS = 10_000;

/** How a member is doing, in one word; `data-state` of its row. */
export type MemberHealth = "leader" | "caught_up" | "catching_up" | "out_of_contact" | "unknown";

export function memberHealth(member: MemberView): MemberHealth {
  if (member.leader) return "leader";
  if (member.last_contact_ms == null && member.lag_entries == null) return "unknown";
  if (member.last_contact_ms != null && member.last_contact_ms > CONTACT_LOST_MS) return "out_of_contact";
  if ((member.lag_entries ?? 0) > PROMOTE_LAG_ENTRIES) return "catching_up";
  return "caught_up";
}

export function voters(view: Pick<ClusterView, "members">): MemberView[] {
  return view.members.filter((m) => m.role === "voter");
}

/** Failures a cluster of `n` voters survives: a majority must remain. */
export function tolerated(n: number): number {
  return n <= 0 ? 0 : Math.floor((n - 1) / 2);
}

export function memberName(member: Pick<MemberView, "node" | "name">): string {
  return member.name ?? t("cluster.member.unnamed", { id: member.node });
}

/** The members, the leader first, then voters, then learners, each by node id. */
export function sortMembers(members: readonly MemberView[]): MemberView[] {
  const rank = (m: MemberView) => (m.leader ? 0 : m.role === "voter" ? 1 : 2);
  return [...members].sort((a, b) => rank(a) - rank(b) || a.node - b.node);
}

/** Why a change cannot be made as asked; the names follow the server's 409 codes. */
export type Blocker = "single" | "changing" | "not_learner" | "not_voter" | "even_voters" | "not_caught_up" | "last_voter" | "no_successor";

/** Something the person should know before confirming; never blocks. */
export type Caveat = "removes_leader" | "removes_self" | "even_after" | "no_tolerance" | "revokes" | "replaces" | "forced" | "reconnect";

export interface ChangePreview {
  votersBefore: number;
  votersAfter: number;
  toleratedBefore: number;
  toleratedAfter: number;
  /** Refusals that `force` overrides (`even_voters`, `not_caught_up`). */
  forceable: Blocker[];
  /** Refusals nothing overrides. */
  blockers: Blocker[];
  caveats: Caveat[];
  /** The voter that leads after a step-down. */
  successor?: MemberView | undefined;
}

function preview(before: number, after: number): ChangePreview {
  return {
    votersBefore: before,
    votersAfter: after,
    toleratedBefore: tolerated(before),
    toleratedAfter: tolerated(after),
    forceable: [],
    blockers: [],
    caveats: [],
  };
}

function caughtUp(member: MemberView): boolean {
  return member.leader || memberHealth(member) === "caught_up";
}

/**
 * Promoting a learner (WP3.1a): only to an odd number of voters (R21) and only once it caught
 * up, unless forced; `replace` removes a voter in the same joint change.
 */
export function promotePreview(view: ClusterView, node: number, options: { force?: boolean; replace?: number | null } = {}): ChangePreview {
  const before = voters(view).length;
  const member = view.members.find((m) => m.node === node);
  const replaced = options.replace != null ? view.members.find((m) => m.node === options.replace && m.role === "voter") : undefined;
  const after = before + 1 - (replaced ? 1 : 0);
  const p = preview(before, after);
  if (view.members.length <= 1) p.blockers.push("single");
  if (view.changing) p.blockers.push("changing");
  if (!member || member.role !== "learner") p.blockers.push("not_learner");
  if (options.replace != null && !replaced) p.blockers.push("not_voter");
  const even = after % 2 === 0;
  const behind = !!member && member.role === "learner" && !caughtUp(member);
  if (options.force) {
    if (even || behind) p.caveats.push("forced");
    if (even) p.caveats.push("even_after");
  } else {
    if (even) p.forceable.push("even_voters");
    if (behind) p.forceable.push("not_caught_up");
  }
  if (replaced) p.caveats.push("replaces");
  return p;
}

/** Removing a member: never the last voter; its certificates are revoked. */
export function removePreview(view: ClusterView, node: number): ChangePreview {
  const before = voters(view).length;
  const member = view.members.find((m) => m.node === node);
  const after = member?.role === "voter" ? before - 1 : before;
  const p = preview(before, after);
  if (view.members.length <= 1) p.blockers.push("single");
  if (view.changing) p.blockers.push("changing");
  if (member?.role === "voter" && before <= 1) p.blockers.push("last_voter");
  if (member?.leader) p.caveats.push("removes_leader");
  if (member && member.node === view.node) p.caveats.push("removes_self");
  if (member?.role === "voter" && after > 0 && after % 2 === 0) p.caveats.push("even_after");
  if (member?.role === "voter" && after > 0 && tolerated(after) === 0) p.caveats.push("no_tolerance");
  p.caveats.push("revokes");
  return p;
}

/** The voter that would lead after a step-down: the most caught-up other voter in contact. */
export function successor(view: ClusterView): MemberView | undefined {
  const candidates = voters(view).filter((m) => !m.leader && memberHealth(m) === "caught_up");
  return [...candidates].sort(
    (a, b) => (a.lag_entries ?? 0) - (b.lag_entries ?? 0) || (a.last_contact_ms ?? 0) - (b.last_contact_ms ?? 0) || a.node - b.node,
  )[0];
}

/** Handing leadership over: needs another caught-up voter. */
export function stepDownPreview(view: ClusterView): ChangePreview {
  const n = voters(view).length;
  const p = preview(n, n);
  if (view.members.length <= 1) p.blockers.push("single");
  if (view.changing) p.blockers.push("changing");
  p.successor = successor(view);
  if (!p.successor && !p.blockers.includes("single")) p.blockers.push("no_successor");
  if (view.leader === view.node) p.caveats.push("reconnect");
  return p;
}

// ---------------------------------------------------------------------------------
// Digests

export type DigestState = "agrees" | "differs" | "missing";

/** The digest most members report; null when none reported one. */
export function majorityDigest(report: DigestReport): string | null {
  const counts = new Map<string, number>();
  for (const m of report.members) if (m.sha256) counts.set(m.sha256, (counts.get(m.sha256) ?? 0) + 1);
  let best: string | null = null;
  let most = 0;
  for (const [digest, count] of counts) {
    if (count > most) {
      best = digest;
      most = count;
    }
  }
  return best;
}

export function digestState(report: DigestReport, member: MemberDigest): DigestState {
  if (!member.sha256 || member.error) return "missing";
  return member.sha256 === majorityDigest(report) && member.revision === report.revision ? "agrees" : "differs";
}

/** The first 16 hexadecimal digits of a digest in groups of four, for comparing at a glance. */
export function shortDigest(hex: string | null | undefined): string {
  if (!hex) return "–";
  return (hex.slice(0, 16).match(/.{1,4}/g) ?? []).join(" ");
}

// ---------------------------------------------------------------------------------
// Words

export function roleWord(role: MemberRole): string {
  return role === "voter" ? t("cluster.role.voter") : t("cluster.role.learner");
}

export function healthWord(health: MemberHealth): string {
  return t(`cluster.health.${health}`);
}

export function quorumWord(state: QuorumKind): string {
  return t(`cluster.quorum.${state}`);
}

/** Milliseconds since the last contact: "80 ms", "4 s", "3 min". */
export function contactText(ms: number | null | undefined): string {
  if (ms == null) return "–";
  if (ms < 1000) return formatNumber(ms, { style: "unit", unit: "millisecond", unitDisplay: "short" });
  const secs = Math.round(ms / 1000);
  if (secs < 120) return formatNumber(secs, { style: "unit", unit: "second", unitDisplay: "short" });
  return formatDuration(Math.round(secs / 60) * 60);
}

/** "Tolerates 1 failure" for `n` voters. */
export function toleranceText(n: number): string {
  return t("cluster.tolerance", { count: tolerated(n) });
}

export function blockerText(blocker: Blocker): string {
  return t(`cluster.blocker.${blocker}`);
}

export function caveatText(caveat: Caveat): string {
  return t(`cluster.caveat.${caveat}`);
}

// ---------------------------------------------------------------------------------
// Paths (the shared table src/app/paths.ts belongs to the shell; these stay here until folded in)

/** The cluster page: members, membership changes and the digest check. */
export const CLUSTER_PATH = "/cluster";

/** The queued changes of this controller and the ones that wait for a decision after a heal. */
export const CLUSTER_QUEUE_PATH = "/cluster/queue";
