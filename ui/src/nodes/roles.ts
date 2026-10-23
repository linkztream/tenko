// The rules of the roles editor (docs/cluster.md, "Changing a node's roles"): the four roles in
// their order, which of them an administrator may switch on a node, the words of the findings
// of the server, and how the editor follows a node through its restart.
import { tDynamic } from "../i18n";
import type { NodeRoles } from "../api/nodes";

/** The roles in canonical order, the order the server lists them in. */
export const ROLES = ["controller", "dns", "dhcp", "probe"] as const;
export type RoleName = (typeof ROLES)[number];

/** Why a role cannot be switched here, or undefined when it can. */
export type Locked = "pinned" | "membership" | "controller_only";

/**
 * Whether `role` can be switched on the node: never while `--roles` pins the roles; the
 * controller role follows the cluster membership; a node without the controller role runs the
 * probe role only until Phase 5.
 */
export function lockOf(role: RoleName, roles: Pick<NodeRoles, "pinned" | "controller">): Locked | undefined {
  if (roles.pinned) return "pinned";
  if (role === "controller") return "membership";
  if (!roles.controller && role !== "probe") return "controller_only";
  return undefined;
}

/** `roles` in canonical order, without duplicates and unknown names. */
export function canonical(roles: readonly string[]): RoleName[] {
  return ROLES.filter((role) => roles.includes(role));
}

export function sameRoles(a: readonly string[], b: readonly string[]): boolean {
  const left = canonical(a);
  const right = canonical(b);
  return left.length === right.length && left.every((role, i) => role === right[i]);
}

/** The roles switched on and off by a change from `from` to `to`. */
export function changeOf(from: readonly string[], to: readonly string[]): { on: RoleName[]; off: RoleName[] } {
  return {
    on: canonical(to).filter((role) => !from.includes(role)),
    off: canonical(from).filter((role) => !to.includes(role)),
  };
}

/** A finding of the server in words: `nodes.roles.finding.<last segment of the code>`, else its English detail. */
export function findingText(finding: { code: string; detail: string; params?: Record<string, string> | null }): string {
  const name = finding.code.split(".").pop() ?? finding.code;
  return tDynamic(`nodes.roles.finding.${name}`, finding.params ?? {}) ?? finding.detail;
}

/**
 * Where a restarting node is: `waiting` until it stops answering or answers with the new roles,
 * `down` while it does not answer, `back` once it runs the new roles, `late` after the deadline.
 */
export type RestartPhase = "waiting" | "down" | "back" | "late";

/** The next phase after a poll: `answer` is the roles the node reported, or undefined when it did not answer. */
export function nextPhase(phase: RestartPhase, wanted: readonly string[], answer: Pick<NodeRoles, "running"> | undefined, late: boolean): RestartPhase {
  if (phase === "back") return phase;
  if (answer?.running && sameRoles(answer.running, wanted)) return "back";
  if (late) return "late";
  return answer ? phase : "down";
}
