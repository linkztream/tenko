// The calls of the cluster page and the partition views: the cluster operations of the OpenAPI
// document (WP3.1a) and the local queue of an isolated controller (WP3.9). The queue calls go
// through `api.*` and `fetchAll`, read as the working model in `model.ts`, until WP3.11c
// moves the views to the generated types. Views call these instead of `api.*`, so the paths live
// in one place.
import { api, type SentWrite } from "../api/client";
import { fetchAll } from "../api/paginate";
import type {
  ClusterView,
  DigestReport,
  PromoteRequest,
  QueueItem,
  QueueRequest,
  QueuedChange,
  ReapplyResult,
  StepDown,
  WriteMethod,
} from "./model";

/** Reads an answer of the document as the working model of `model.ts` (WP3.11c removes this). */
function asModel<T>(answer: Promise<unknown>): Promise<T> {
  return answer as Promise<T>;
}

export function listMembers(signal?: AbortSignal): Promise<ClusterView> {
  return api.get("/api/v1/cluster/members", { signal });
}

export function promoteMember(node: number, request: PromoteRequest = {}): Promise<ClusterView> {
  return api.post("/api/v1/cluster/members/{id}/promote", { path: { id: node }, body: request });
}

export function removeMember(node: number): Promise<ClusterView> {
  return api.delete("/api/v1/cluster/members/{id}", { path: { id: node } });
}

export function stepDown(): Promise<StepDown> {
  return api.post("/api/v1/cluster/step-down");
}

/** The digests of every member at `revision` (default: the leader's applied revision). */
export function digests(revision?: number, signal?: AbortSignal): Promise<DigestReport> {
  return api.get("/api/v1/cluster/digests", { query: { revision }, signal });
}

/** The local queue of this controller. */
export async function listQueue(signal?: AbortSignal): Promise<{ items: QueueItem[]; revision: number | string }> {
  const { items, revision } = await fetchAll<QueueItem>("/api/v1/queue", { signal });
  return { items, revision };
}

/** Queues a write the controller refused for want of a quorum; answers the item with its local plan. */
export function queueChange(request: QueueRequest): Promise<QueueItem> {
  return asModel(api.post("/api/v1/queue", { body: request as never }));
}

export function cancelQueued(id: string): Promise<undefined> {
  return asModel(api.delete("/api/v1/queue/{id}", { path: { id } }));
}

/** The caller's queued changes after a heal: applied ones and the ones with a conflict. */
export async function listQueuedChanges(signal?: AbortSignal): Promise<{ items: QueuedChange[]; revision: number | string }> {
  const { items, revision } = await fetchAll<QueuedChange>("/api/v1/queue/conflicts", { signal });
  return { items, revision };
}

/** Plans a queued change again (`dryRun`), or applies it with the acknowledged warning codes. */
export function reapplyQueued(
  id: string,
  options: { dryRun: boolean; acknowledge?: readonly string[] | undefined; ifMatch?: number | undefined },
): Promise<ReapplyResult> {
  return asModel(api.post("/api/v1/queue/conflicts/{id}/reapply", {
    path: { id },
    query: { dry_run: options.dryRun ? true : undefined, acknowledge: options.acknowledge?.length ? [...options.acknowledge] : undefined },
    ifMatch: options.ifMatch,
  }));
}

export function discardQueued(id: string, ifMatch?: number): Promise<undefined> {
  return asModel(api.delete("/api/v1/queue/conflicts/{id}", { path: { id }, ifMatch }));
}

/** The body of `POST /queue` for a refused write: the request as it was sent, without `dry_run`. */
export function queueRequestOf(write: SentWrite): QueueRequest {
  const url = new URL(write.url, "http://controller.example.test");
  const query: Record<string, string> = {};
  for (const [name, value] of url.searchParams) if (name !== "dry_run") query[name] = value;
  return {
    method: write.method as WriteMethod,
    path: url.pathname,
    query: Object.keys(query).length ? query : null,
    body: write.body ?? null,
    if_match: write.ifMatch === undefined ? null : String(write.ifMatch),
  };
}
