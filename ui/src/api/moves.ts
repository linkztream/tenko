// The move API (IPAM-19, WP1.4b): one module, so the move preview and its mock share one
// shape. POST /api/v1/moves?dry_run=true answers the preview (nothing changes); without the
// dry run it starts one job per moved address, all in one group, and answers 202. Retries of
// one confirmation reuse the Idempotency-Key (a replay answers with `replayed: true`).
import { api, newIdempotencyKey } from "./client";
import type { components } from "./generated/schema";

type S = components["schemas"];

export type MoveRequest = S["MoveRequest"];
export type MovePreview = S["MovePreview"];
export type MoveItem = S["MoveItem"];
export type MoveStepPreview = S["MoveStepPreview"];
export type MoveTarget = S["MoveTarget"];
export type MoveDns = S["MoveDns"];
export type MoveJob = S["MoveJob"];
export type MoveSubmitted = S["MoveSubmitted"];
export type MoveTimeoutSource = S["MoveTimeoutSource"];

/** The move preview: nothing changes. */
export function previewMove(request: MoveRequest, signal?: AbortSignal): Promise<MovePreview> {
  return api.post("/api/v1/moves", { query: { dry_run: true }, body: request, signal }) as Promise<MovePreview>;
}

/** Starts the moves: one job per moved address. */
export function submitMove(request: MoveRequest, idempotencyKey: string = newIdempotencyKey()): Promise<MoveSubmitted> {
  return api.post("/api/v1/moves", { body: request, idempotencyKey }) as Promise<MoveSubmitted>;
}
