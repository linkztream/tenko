// The requests of the lease and history views (WP7.5) that are not list reads (the lists go
// through the grid's list source): the release of a lease, this server's node and the state of
// its `dhcp` role.
import { api } from "../../api/client";
import type { Lease, NodeStatus } from "./model";

/** Releases an active lease; the reason is for the audit record. Answers the released lease. */
export function releaseLease(lease: Pick<Lease, "addr" | "vrf">, reason: string): Promise<Lease> {
  const text = reason.trim();
  return api.post("/api/v1/dhcp/leases/{addr}/release", {
    path: { addr: lease.addr },
    body: { vrf: lease.vrf, ...(text !== "" ? { reason: text } : {}) },
  });
}

/** The id of this server's node, or undefined when it has none. */
export async function thisNode(signal?: AbortSignal): Promise<number | undefined> {
  const status = await api.get("/api/v1/system/status", { signal });
  const id = status.node.id;
  return id === null || id === undefined ? undefined : Number(id);
}

/** The state of the `dhcp` role of a node. */
export function nodeDhcp(id: number, signal?: AbortSignal): Promise<NodeStatus> {
  return api.get("/api/v1/nodes/{id}/dhcp", { path: { id }, signal });
}

/** The state of the `dhcp` role of this server's node; undefined when the server has no node. */
export async function thisNodeDhcp(signal?: AbortSignal): Promise<NodeStatus | undefined> {
  const id = await thisNode(signal);
  return id === undefined ? undefined : nodeDhcp(id, signal);
}
