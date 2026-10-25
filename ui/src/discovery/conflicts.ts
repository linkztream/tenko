// Address conflicts (the rules `conflict_shared_address` and `conflict_address_taken`): which
// proposals they are, the hosts they name, and "keep both", which closes the conflict as it
// stands. The proposal's parameters carry the hosts in conflict as identifiers (`hosts`, the
// intended host first for a taken address) and, for a taken address, the host whose own claim
// comes only from a stopped guest (`dormant_hosts`).
import { ANY_REVISION, api } from "../api/client";
import type { Decision, Proposal } from "./api";

/** The rules of the address conflicts that can be decided by decommissioning a host or keeping both. */
export const ADDRESS_CONFLICT_RULES: readonly string[] = ["ipam.reconcile.conflict_shared_address", "ipam.reconcile.conflict_address_taken"];

/** Whether the proposal is an open address conflict. */
export function isAddressConflict(p: Pick<Proposal, "rule" | "state">): boolean {
  return p.state === "open" && ADDRESS_CONFLICT_RULES.includes(p.rule);
}

/** Identifiers from a parameter that lists them separated by commas and spaces. */
function idList(text: string | undefined): string[] {
  return (text ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id !== "");
}

/** The hosts in the conflict, and those among them whose claim is only a stopped guest's. */
export function conflictHosts(p: Pick<Proposal, "params">): { hosts: string[]; dormant: string[] } {
  const hosts = idList(p.params?.hosts);
  const dormant = idList(p.params?.dormant_hosts);
  return { hosts, dormant };
}

/** Keeps both claims: the conflict is closed without a change in IPAM. The reason is optional. */
export function keepProposal(proposal: Pick<Proposal, "id" | "revision">, reason: string): Promise<Decision> {
  const trimmed = reason.trim();
  return api.post("/api/v1/proposals/{id}/keep", {
    path: { id: proposal.id },
    body: { reason: trimmed === "" ? null : trimmed },
    ifMatch: proposal.revision ?? ANY_REVISION,
  });
}
