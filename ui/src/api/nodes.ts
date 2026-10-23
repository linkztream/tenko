// The node routes of the API (docs/cluster.md, section 9): the enrolled nodes with their live
// connection, revocation, and the enrolment tokens. A token's text is in the answer of its
// creation only (`Cache-Control: no-store`); nothing here keeps it.
import { ANY_REVISION, api } from "./client";
import type { components } from "./generated/schema";

type S = components["schemas"];

export type NodeView = S["NodeView"];
export type ConnectionView = S["ConnectionView"];
export type CertificateRef = S["CertificateRef"];
export type EnrolmentView = S["EnrolmentView"];
export type NewEnrolment = S["NewEnrolment"];
export type CreatedEnrolment = S["CreatedEnrolment"];
export type ClusterStatus = S["ClusterStatus"];

/** The roles a token may grant; a controller joins differently (Slice 3). */
export const ENROL_ROLES = ["probe", "dns", "dhcp"] as const;
export type EnrolRole = (typeof ENROL_ROLES)[number];

export function getNode(id: number | string, signal?: AbortSignal): Promise<NodeView> {
  return api.get("/api/v1/nodes/{id}", { path: { id }, signal });
}

/** Revokes a node: its certificates are refused from now on and its connections close. */
export function revokeNode(id: number | string): Promise<undefined> {
  return api.delete("/api/v1/nodes/{id}", { path: { id }, ifMatch: ANY_REVISION }) as Promise<undefined>;
}

export async function listEnrolments(signal?: AbortSignal): Promise<EnrolmentView[]> {
  const answer = await api.get("/api/v1/nodes/enrolments", { signal });
  return answer.items;
}

/**
 * Creates a token. No `Idempotency-Key`: the answer carries the token, which the server does
 * not keep for a replay; a retried request makes a second token, which the list shows.
 */
export function createEnrolment(body: NewEnrolment): Promise<CreatedEnrolment> {
  return api.post("/api/v1/nodes/enrolments", { body, idempotencyKey: null });
}

export function deleteEnrolment(id: string): Promise<undefined> {
  return api.delete("/api/v1/nodes/enrolments/{id}", { path: { id }, ifMatch: ANY_REVISION }) as Promise<undefined>;
}

// node-roles: the roles of a node (docs/operations.md, "Changing a node's roles").
export type NodeRoles = S["NodeRoles"];

export function getNodeRoles(id: number | string, signal?: AbortSignal): Promise<NodeRoles> {
  return api.get("/api/v1/nodes/{id}/roles", { path: { id }, signal });
}

/** Sets the roles a node runs from its next start; `revision` is the one read (`If-Match`). */
export function putNodeRoles(id: number | string, roles: string[], revision?: number | null): Promise<NodeRoles> {
  return api.put("/api/v1/nodes/{id}/roles", { path: { id }, body: { roles }, ifMatch: revision ?? undefined });
}
// node-roles: end.
