// The only module of the updates area that talks to the API (OPS-24, OPS-25): the update
// status, the check, the manifest, the install and upload, the what-is-new notes, the module
// switch, and the two reads the install progress needs (a job and the health probe).
//
// The release upload is the one request the typed client cannot send: its body is the raw
// release file (`application/octet-stream`, up to hundreds of megabytes), where the client
// sends JSON or multipart only. It uses `fetch` here, with the same problem handling.
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { ApiError, CLIENT_CODES, toProblem } from "../api/problem";
import type { JobDetail } from "../api/types";

type S = components["schemas"];

export type UpdateStatus = S["UpdateStatus"];
export type Release = S["Release"];
export type ReleaseAsset = S["ReleaseAsset"];
export type InstallBlock = S["InstallBlock"];
export type InstallPolicy = S["InstallPolicy"];
export type InstallStarted = S["InstallStarted"];
export type UpdateAttempt = S["UpdateAttempt"];
export type UpdateCheck = S["UpdateCheck"];
export type WhatsNewNotes = S["WhatsNew"];
export type ModuleSettings = S["ModuleSettings"];
export type ModuleName = S["ModuleSet"][number];

// ---------------------------------------------------------------------------------
// Updates (administrators)

export function readUpdates(signal?: AbortSignal): Promise<UpdateStatus> {
  return api.get("/api/v1/system/updates", { signal });
}

/** Asks the release source now (409 `update.check_off`, 502 `update.fetch_failed`). */
export function checkUpdates(): Promise<UpdateStatus> {
  return api.post("/api/v1/system/updates/check");
}

/** Hands the server a `releases.json` read from a file (air-gapped installations). */
export function uploadManifest(manifest: unknown): Promise<UpdateStatus> {
  return api.put("/api/v1/system/updates/manifest", { body: manifest as never });
}

/** Installs a version from the release source; `key` identifies the one logical install. */
export function installVersion(version: string, key: string): Promise<InstallStarted> {
  return api.post("/api/v1/system/updates/install", { body: { version }, idempotencyKey: key });
}

/**
 * Installs a release file the administrator chose. No `Idempotency-Key`: the server
 * buffers keyed requests under a smaller size limit than an upload.
 */
export async function uploadRelease(file: Blob, version: string, signal?: AbortSignal): Promise<InstallStarted> {
  const url = `/api/v1/system/updates/upload?version=${encodeURIComponent(version)}`;
  let res: Response;
  try {
    // eslint-disable-next-line no-restricted-syntax -- a raw file body, which the typed client cannot send
    res = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/octet-stream" },
      body: file,
      credentials: "same-origin",
      signal: signal ?? null,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError({ status: 0, code: CLIENT_CODES.network, title: "", detail: String(err) });
  }
  let parsed: unknown;
  try {
    const text = await res.text();
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  if (!res.ok) throw new ApiError(toProblem(res.status, parsed));
  return parsed as InstallStarted;
}

// ---------------------------------------------------------------------------------
// What is new (every signed-in user)

export function readWhatsNew(signal?: AbortSignal): Promise<WhatsNewNotes> {
  return api.get("/api/v1/system/updates/whats-new", { signal });
}

export function markWhatsNewSeen(): Promise<void> {
  return api.post("/api/v1/system/updates/whats-new/seen").then(() => undefined);
}

// ---------------------------------------------------------------------------------
// Modules (OPS-25)

export function readModules(signal?: AbortSignal): Promise<ModuleSettings> {
  return api.get("/api/v1/system/modules", { signal });
}

export function writeModules(modules: readonly ModuleName[]): Promise<ModuleSettings> {
  return api.put("/api/v1/system/modules", { body: { modules: [...modules] } });
}

// ---------------------------------------------------------------------------------
// The install in progress

export function readJob(id: string, signal?: AbortSignal): Promise<JobDetail> {
  return api.get("/api/v1/jobs/{id}", { path: { id }, signal });
}

/** The version the server answers with on the public health probe. */
export async function readHealthVersion(signal?: AbortSignal): Promise<string> {
  const health = await api.get("/api/v1/health", { signal });
  return health.version;
}

/** Answers that mean "this server has nothing to show here": no right, no service. */
export function isQuiet(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.status === 403 || err.status === 404 || err.status === 501 || err.status === 503);
}
