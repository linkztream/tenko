// Dormant claims: a host fact whose guest is stopped (`power` is `stopped`) says that the
// address is configured on the guest, not that it is in use. The host page and the address
// page say so; the reconciler treats such a claim as the weakest one in an address conflict.
import type { ObservedFact } from "./api";
import { isCurrent } from "./model";

export interface DormantClaim {
  /** An address configured on the stopped guest. */
  ip: string;
  /** The guest, as its source names it. */
  name: string;
}

/** The addresses configured on stopped guests according to the current host facts, once each. */
export function dormantClaims(facts: readonly ObservedFact[], now = Date.now()): DormantClaim[] {
  const out: DormantClaim[] = [];
  for (const fact of facts) {
    const o = fact.observed;
    if (o.type !== "host" || o.data.power !== "stopped" || !isCurrent(fact, now)) continue;
    const name = o.data.name ?? o.data.external_id;
    for (const ip of o.data.ips ?? []) {
      if (!out.some((c) => c.ip === ip && c.name === name)) out.push({ ip, name });
    }
  }
  return out;
}
