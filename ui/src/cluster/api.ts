// The calls of the cluster page and the partition views: the cluster operations of the OpenAPI
// document (WP3.1a) and the local queue of an isolated controller (WP3.9). Views call these
// instead of `api.*`, so the paths live in one place.
import { api, type SentWrite } from "../api/client";
import type {
  ClusterView,
  DigestReport,
  PromoteRequest,
  QueueItemView,
  QueueList,
  QueuedChangeList,
  QueuedRequest,
  QueueRequest,
  ReapplyResult,
  StepDown,
} from "./model";

/** The API base the queue paths are relative to. */
const API_BASE = "/api/v1";

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

/** The caller's items in the local queue of this controller, oldest first. */
export function listQueue(signal?: AbortSignal): Promise<QueueList> {
  return api.get("/api/v1/queue", { signal });
}

/** Queues a write the controller refused for want of a quorum; answers the item with its local plan. */
export function queueChange(request: QueueRequest): Promise<QueueItemView> {
  return api.post("/api/v1/queue", { body: request as QueuedRequest });
}

/** Withdraws an item from the local queue before the heal. */
export function cancelQueued(id: string): Promise<undefined> {
  return api.delete("/api/v1/queue/{id}", { path: { id } });
}

/** The caller's queued changes after a heal: applied ones, conflicts and expired ones. */
export function listQueuedChanges(signal?: AbortSignal): Promise<QueuedChangeList> {
  return api.get("/api/v1/queue/conflicts", { signal });
}

/**
 * Plans a queued change again (`dryRun`), or applies it with the acknowledged warning codes. The
 * server adds the acknowledgements of the original request; the change is confirmed against the
 * current state, so no `If-Match` is sent.
 */
export async function reapplyQueued(
  id: string,
  options: { dryRun: boolean; acknowledge?: readonly string[] | undefined },
): Promise<ReapplyResult> {
  const answer = await api.post("/api/v1/queue/conflicts/{id}/reapply", {
    path: { id },
    query: { dry_run: options.dryRun ? true : undefined, acknowledge: options.acknowledge?.length ? options.acknowledge.join(",") : undefined },
  });
  // The document leaves the answer open: it is the answer of the endpoint the change re-applies.
  return answer as unknown as ReapplyResult;
}

/** Discards a settled change: a conflict or an expired change the person gives up, or an applied one they have seen. */
export function discardQueued(id: string): Promise<undefined> {
  return api.delete("/api/v1/queue/conflicts/{id}", { path: { id } });
}

/**
 * The body of `POST /queue` for a refused write: the request as it was sent, the path below the
 * API base and the raw query string without `dry_run`.
 */
export function queueRequestOf(write: SentWrite): QueueRequest {
  const url = new URL(write.url, "http://controller.example.test");
  url.searchParams.delete("dry_run");
  const query = url.searchParams.toString();
  return {
    method: write.method.toUpperCase(),
    path: url.pathname.startsWith(API_BASE) ? url.pathname.slice(API_BASE.length) : url.pathname,
    query: query || null,
    body: write.body ?? null,
    if_match: write.ifMatch === undefined ? null : String(write.ifMatch),
  };
}
