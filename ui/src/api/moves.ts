// The move API (IPAM-19, WP1.4b, WP2.8): one module, so the move preview and its mock share one
// shape. POST /api/v1/moves?dry_run=true answers the preview (nothing changes, the network
// controllers are only read); without the dry run it starts one job per moved address, all in
// one group, and answers 202. Retries of one confirmation reuse the Idempotency-Key (a replay
// answers with `replayed: true`), and `expect_fingerprint` makes the server run the confirmed
// plan or nothing (409 `ipam.move.plan_changed`).
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
export type MoveTiming = S["MoveTiming"];
export type MovePrepare = S["MovePrepare"];
export type MoveActivitySource = S["MoveActivitySource"];
export type MoveL2 = S["MoveL2"];
export type MoveL2Action = S["MoveL2Action"];
export type MoveAttachment = S["MoveAttachment"];
export type MoveL2Problem = S["MoveL2Problem"];
export type MoveNudge = S["MoveNudge"];
export type MoveNudgeAction = S["MoveNudgeAction"];
export type NudgeChange = S["NudgeChange"];
export type MoveMedium = S["MoveMedium"];
export type AttachmentChange = S["AttachmentChange"];
export type ControllerInfo = S["ControllerInfo"];
export type DiffEntry = S["DiffEntry"];

/** The preview of a move: nothing changes. */
export function previewMove(request: MoveRequest, signal?: AbortSignal): Promise<MovePreview> {
  return api.post("/api/v1/moves", { query: { dry_run: true }, body: request, signal }) as Promise<MovePreview>;
}

/** Starts the moves: one job per moved address. */
export function submitMove(request: MoveRequest, idempotencyKey: string = newIdempotencyKey()): Promise<MoveSubmitted> {
  return api.post("/api/v1/moves", { body: request, idempotencyKey }) as Promise<MoveSubmitted>;
}

// ---------------------------------------------------------------------------------
// The output of the L2 step of a move job

/** The step kind of the L2 change through the network controller. */
export const MOVE_CONTROLLER_STEP = "ipam.move.controller";

/**
 * The receipt of a controller write (`NetworkReceipt` in crates/tenko-ipam/src/vlan/controllers.rs);
 * `token` is opaque to the UI.
 */
export interface MoveL2Receipt {
  connector: string;
  dry_run: boolean;
  applied_at: string;
  verified: boolean;
  undo_steps: number;
  token: string;
}

/**
 * What the `ipam.move.controller` step did: its output is this JSON, hex-encoded in the step
 * record (`MoveL2Output` in crates/tenko-ipam/src/moves/steps.rs). The diff is the controller's
 * read-back right before the write; the receipt's undo steps put the device back on rollback.
 */
export interface MoveL2Output {
  connector: string;
  change: AttachmentChange;
  diff?: DiffEntry[];
  warnings?: string[];
  read_at: string;
  /** The controller had the change already: nothing was written. */
  unchanged?: boolean;
  /** An interrupted attempt may have written without a receipt: a rollback asks a person. */
  unknown_write?: boolean;
  receipt?: MoveL2Receipt | null;
}

/** Decodes hex-encoded JSON that is an object with the given members; undefined when absent or malformed. */
function decodeHexJson(hex: string | null | undefined, members: readonly string[]): unknown {
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return undefined;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== "object" || !members.every((m) => m in value)) return undefined;
    return value;
  } catch {
    return undefined;
  }
}

function encodeHexJson(value: unknown): string {
  return Array.from(new TextEncoder().encode(JSON.stringify(value)), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Decodes the hex-encoded JSON output of an `ipam.move.controller` step; undefined when absent or malformed. */
export function decodeMoveL2Output(hex: string | null | undefined): MoveL2Output | undefined {
  return decodeHexJson(hex, ["change", "connector"]) as MoveL2Output | undefined;
}

/** Encodes an L2 step output the way the server stores it (for the mock and tests). */
export function encodeMoveL2Output(output: MoveL2Output): string {
  return encodeHexJson(output);
}

// ---------------------------------------------------------------------------------
// The output of the nudge step of a move job (ADR 0028)

/** The step kind of the bounce of a switch port or the kick of a wireless client. */
export const MOVE_NUDGE_STEP = "ipam.move.nudge";

/** What the connector host reports of a bounce or a kick (the outcome is flattened: `code` and `detail` for failed and stuck). */
export interface MoveNudgeReport {
  connector: string;
  change: NudgeChange;
  at?: string;
  /** When the port was up again (a bounce). */
  up_at?: string;
  outcome: "done" | "failed" | "stuck";
  code?: string;
  detail?: string;
}

/**
 * What the `ipam.move.nudge` step did (`MoveNudgeOutput` in crates/tenko-ipam/src/moves/steps.rs;
 * not in the OpenAPI document): the client came back by itself, or the report of the bounce or
 * the kick, or the guardrail problem that stopped it. `interrupted`: the step ran again after an
 * interruption and did not nudge a second time.
 */
export interface MoveNudgeOutput {
  change: NudgeChange;
  reappeared_at?: string;
  reappeared_by?: "dhcp" | "lease";
  report?: MoveNudgeReport;
  problem?: MoveL2Problem;
  interrupted?: boolean;
}

/** Decodes the hex-encoded JSON output of an `ipam.move.nudge` step; undefined when absent or malformed. */
export function decodeMoveNudgeOutput(hex: string | null | undefined): MoveNudgeOutput | undefined {
  return decodeHexJson(hex, ["change"]) as MoveNudgeOutput | undefined;
}

/** Encodes a nudge step output the way the server stores it (for the mock and tests). */
export function encodeMoveNudgeOutput(output: MoveNudgeOutput): string {
  return encodeHexJson(output);
}
