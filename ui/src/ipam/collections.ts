// The IPAM collections with the operations every one of them has (IPAM-09): soft delete,
// restore and history. The API paths are literal per collection so the typed client checks
// them against the OpenAPI document.
import { api, type Revision } from "../api/client";
import type { HistoryEntry, Page, WriteResponse } from "../api/types";
import { writeQuery } from "./plan/describe";

export type Collection =
  | "tenants"
  | "vrfs"
  | "sites"
  | "vlans"
  | "prefixes"
  | "ranges"
  | "addresses"
  | "hosts"
  | "interfaces";

/** Collections whose delete can take the dependants along (`cascade=true`). */
export const CASCADING: ReadonlySet<Collection> = new Set(["prefixes", "hosts", "interfaces"]);

export interface WriteOptions {
  dryRun: boolean;
  acknowledge: string[];
  revision?: Revision | null | undefined;
  cascade?: boolean;
}

type Answer = WriteResponse<unknown>;

/** Soft-deletes an object (or previews it with `dryRun`). */
export function deleteObject(collection: Collection, id: string, o: WriteOptions): Promise<Answer> {
  const query = { ...writeQuery(o.dryRun, o.acknowledge), cascade: o.cascade && CASCADING.has(collection) ? true : undefined };
  const options = { path: { id }, query, ifMatch: o.revision ?? undefined };
  switch (collection) {
    case "tenants":
      return api.delete("/api/v1/tenants/{id}", options);
    case "vrfs":
      return api.delete("/api/v1/vrfs/{id}", options);
    case "sites":
      return api.delete("/api/v1/sites/{id}", options);
    case "vlans":
      return api.delete("/api/v1/vlans/{id}", options);
    case "prefixes":
      return api.delete("/api/v1/prefixes/{id}", options);
    case "ranges":
      return api.delete("/api/v1/ranges/{id}", options);
    case "addresses":
      return api.delete("/api/v1/addresses/{id}", options);
    case "hosts":
      return api.delete("/api/v1/hosts/{id}", options);
    case "interfaces":
      return api.delete("/api/v1/interfaces/{id}", options);
  }
}

/** Restores a soft-deleted object (or previews it with `dryRun`). */
export function restoreObject(collection: Collection, id: string, o: WriteOptions): Promise<Answer> {
  const options = { path: { id }, query: writeQuery(o.dryRun, o.acknowledge), ifMatch: o.revision ?? undefined };
  switch (collection) {
    case "tenants":
      return api.post("/api/v1/tenants/{id}/restore", options);
    case "vrfs":
      return api.post("/api/v1/vrfs/{id}/restore", options);
    case "sites":
      return api.post("/api/v1/sites/{id}/restore", options);
    case "vlans":
      return api.post("/api/v1/vlans/{id}/restore", options);
    case "prefixes":
      return api.post("/api/v1/prefixes/{id}/restore", options);
    case "ranges":
      return api.post("/api/v1/ranges/{id}/restore", options);
    case "addresses":
      return api.post("/api/v1/addresses/{id}/restore", options);
    case "hosts":
      return api.post("/api/v1/hosts/{id}/restore", options);
    case "interfaces":
      return api.post("/api/v1/interfaces/{id}/restore", options);
  }
}

/** One page of an object's history, newest first. */
export function historyPage(
  collection: Collection,
  id: string,
  cursor?: string | null,
  signal?: AbortSignal,
): Promise<Page<HistoryEntry>> {
  const options = { path: { id }, query: { cursor: cursor ?? undefined, limit: 100 }, signal };
  switch (collection) {
    case "tenants":
      return api.get("/api/v1/tenants/{id}/history", options);
    case "vrfs":
      return api.get("/api/v1/vrfs/{id}/history", options);
    case "sites":
      return api.get("/api/v1/sites/{id}/history", options);
    case "vlans":
      return api.get("/api/v1/vlans/{id}/history", options);
    case "prefixes":
      return api.get("/api/v1/prefixes/{id}/history", options);
    case "ranges":
      return api.get("/api/v1/ranges/{id}/history", options);
    case "addresses":
      return api.get("/api/v1/addresses/{id}/history", options);
    case "hosts":
      return api.get("/api/v1/hosts/{id}/history", options);
    case "interfaces":
      return api.get("/api/v1/interfaces/{id}/history", options);
  }
}
