// How a member of the controller cluster is doing (OPS-03): the rule the cluster page and the top
// bar's node chip share. Kept apart from model.ts so the shell can read it without the rest.
import type { components } from "../api/generated/schema";

type MemberView = components["schemas"]["MemberView"];

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

/** Whether a member lags behind the leader or is out of its contact. */
export function isBehind(member: MemberView): boolean {
  const health = memberHealth(member);
  return health === "catching_up" || health === "out_of_contact";
}
