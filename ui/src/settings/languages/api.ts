// The requests of the languages page (API-21): the languages with their packs, the upload, the
// report, preview, activation, discard and removal of a pack, and the template's address.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

type S = components["schemas"];

export type PackList = S["PackList"];
export type PackInfo = S["PackInfo"];
export type PackVersion = S["PackVersion"];
export type PackStatus = S["PackStatus"];
export type PackReport = S["PackReport"];
export type PackProblem = S["PackProblem"];
export type PackUpload = S["PackUpload"];

export function listPacks(signal?: AbortSignal): Promise<PackList> {
  return api.get("/api/v1/i18n/packs", { signal });
}

/**
 * Uploads an XLIFF 2.0 document; the server validates it and keeps it as the candidate of its
 * language. No `Idempotency-Key`: the server buffers keyed requests under a smaller size limit
 * than a pack.
 */
export function uploadPack(file: File): Promise<PackUpload> {
  const form = new FormData();
  form.append("file", file, file.name);
  return api.post("/api/v1/i18n/packs", { body: form, idempotencyKey: null });
}

export function packReport(tag: string, signal?: AbortSignal): Promise<PackReport> {
  return api.get("/api/v1/i18n/packs/{tag}/report", { path: { tag }, signal });
}

/** Marks the candidate previewed; the preview itself runs in this tab (src/i18n/remote.ts). */
export function previewPack(tag: string): Promise<PackInfo> {
  return api.post("/api/v1/i18n/packs/{tag}/preview", { path: { tag } });
}

export function activatePack(tag: string): Promise<PackInfo> {
  return api.post("/api/v1/i18n/packs/{tag}/activate", { path: { tag } });
}

export function discardCandidate(tag: string): Promise<PackInfo> {
  return api.delete("/api/v1/i18n/packs/{tag}/candidate", { path: { tag } });
}

/** Removes a language that is not built in, or reverts a built-in one to its own texts. */
export async function removePack(tag: string): Promise<void> {
  await api.delete("/api/v1/i18n/packs/{tag}", { path: { tag } });
}

/** The address of the template of a language (the English template without `tag`). */
export function templateUrl(tag?: string): string {
  const base = "/api/v1/i18n/template.xlf";
  return tag ? `${base}?language=${encodeURIComponent(tag)}` : base;
}

/** The largest pack the server accepts (8 MiB). */
export const MAX_PACK_BYTES = 8 * 1024 * 1024;
