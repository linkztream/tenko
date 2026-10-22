// The requests of the recursion page's status block (WP10.1): the node this server is, the
// recursive resolver of that node (`GET /nodes/{id}/dns/recursion`) and the priming it can be
// asked for now (`POST /nodes/{id}/dns/recursion/prime`, the node command `dns.recursion.prime`).
// In Phase 2 the role runs in the controller's own process, so the one node is this one.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

export type RecursionStatus = components["schemas"]["RecursionStatus"];

/** This server's node id, or `null` when it has no node. */
export async function recursionNode(signal?: AbortSignal): Promise<number | null> {
  const status = await api.get("/api/v1/system/status", { signal });
  const id = status.node.id;
  return id === null || id === undefined ? null : Number(id);
}

export function readRecursion(id: number, signal?: AbortSignal): Promise<RecursionStatus> {
  return api.get("/api/v1/nodes/{id}/dns/recursion", { path: { id }, signal });
}

/** Asks the node to prime its resolver now; the outcome shows in the next status. */
export async function primeRecursion(id: number): Promise<void> {
  await api.post("/api/v1/nodes/{id}/dns/recursion/prime", { path: { id } });
}
