// The import and export API (IPAM-11, MIG-14), in one module so a change of the endpoints
// touches only this file. The wizard works with these types and functions only.
//
//   POST   /imports              multipart `files` (repeated), no Idempotency-Key: the
//                                server buffers keyed requests under a smaller limit than
//                                the 20 MB of an upload -> 201 ImportView
//   GET    /imports/{id}         ImportView (410 once the staged upload expired)
//   PUT    /imports/{id}/mapping Mapping -> ImportView
//   GET    /imports/{id}/preview?rows=N -> ImportPreview
//   POST   /imports/{id}/apply   { acknowledge } -> 202 { job_id }
//   DELETE /imports/{id}         204
//   GET    /exports/{prefixes,addresses,hosts}.csv  streamed CSV in the import vocabulary
import { api } from "../api/client";
import type { components } from "../api/generated/schema";

type S = components["schemas"];

export type ImportView = S["ImportView"];
export type ImportState = S["ImportState"];
export type SheetAnalysis = S["SheetAnalysis"];
export type ColumnAnalysis = S["ColumnAnalysis"];
export type Mapping = S["Mapping"];
export type SheetMapping = S["SheetMapping"];
export type ColumnMapping = S["ColumnMapping"];
export type ImportOptions = S["ImportOptions"];
export type SheetKind = S["SheetKind"];
export type MaskSource = S["MaskSource"];
export type TargetInfo = S["TargetInfo"];
export type ImportPreview = S["ImportPreview"];
export type PreviewRow = S["PreviewRow"];
export type ItemKey = S["ItemKey"];
export type ItemAction = S["ItemAction"];
export type LossItem = S["LossItem"];
export type SheetLoss = S["SheetLoss"];
export type Severity = S["Severity"];
export type Proposal = S["Proposal"];
export type CredentialNotice = S["CredentialNotice"];
export type ConflictPolicy = S["ConflictPolicy"];
export type ShapeCounts = S["ShapeCounts"];

/** Largest upload the server accepts (20 MiB of files, plus the multipart framing). */
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
/** Extensions the server reads. */
export const ACCEPTED = [".csv", ".txt", ".xlsx", ".xls", ".ods"] as const;
/** Rows of the preview's row table. */
export const PREVIEW_ROWS = 200;

export function uploadImport(files: readonly File[], signal?: AbortSignal): Promise<ImportView> {
  const form = new FormData();
  for (const file of files) form.append("files", file, file.name);
  return api.post("/api/v1/imports", { body: form, idempotencyKey: null, signal });
}

export function readImport(id: string, signal?: AbortSignal): Promise<ImportView> {
  return api.get("/api/v1/imports/{id}", { path: { id }, signal });
}

export function saveMapping(id: string, mapping: Mapping): Promise<ImportView> {
  return api.put("/api/v1/imports/{id}/mapping", { path: { id }, body: mapping });
}

export function previewImport(id: string, signal?: AbortSignal): Promise<ImportPreview> {
  return api.get("/api/v1/imports/{id}/preview", { path: { id }, query: { rows: PREVIEW_ROWS }, signal });
}

export async function applyImport(id: string, acknowledge: readonly string[], idempotencyKey: string): Promise<string> {
  const accepted = await api.post("/api/v1/imports/{id}/apply", {
    path: { id },
    body: { acknowledge: [...acknowledge] },
    idempotencyKey,
  });
  return accepted.job_id;
}

export async function discardImport(id: string): Promise<void> {
  await api.delete("/api/v1/imports/{id}", { path: { id } });
}

export type ExportKind = "prefixes" | "addresses" | "hosts";
export const EXPORT_KINDS: readonly ExportKind[] = ["prefixes", "addresses", "hosts"];

/** The download URL of a CSV export (a plain link: the browser streams it to a file). */
export function exportUrl(kind: ExportKind): string {
  return `/api/v1/exports/${kind}.csv`;
}
