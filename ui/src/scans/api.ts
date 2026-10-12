// The calls of the scan pages and the probe configuration: the `scans` operations of the
// OpenAPI document (SCAN-09). Views call these instead of `api.*`, so the paths live in one place.
import { api } from "../api/client";
import { fetchAll, type AllItems } from "../api/paginate";
import type {
  KillSwitchResult,
  ProbeConfigView,
  ProbeList,
  ScanConfig,
  ScanRequest,
  ScanView,
} from "./model";

/** Starts a scan; the answer is the queued run, which `getScan` follows. */
export function createScan(request: ScanRequest): Promise<ScanView> {
  return api.post("/api/v1/scans", { body: request });
}

/** Every run, newest first, with the counts of its diff only. */
export function listScans(signal?: AbortSignal): Promise<AllItems<ScanView>> {
  return fetchAll<ScanView>("/api/v1/scans", { signal });
}

/** One run with every item of its diff. */
export function getScan(id: string, signal?: AbortSignal): Promise<ScanView> {
  return api.get("/api/v1/scans/{id}", { path: { id }, signal });
}

/** Every probe with its kill switch and the state of its configuration. */
export function listProbes(signal?: AbortSignal): Promise<ProbeList> {
  return api.get("/api/v1/scans/probes", { signal });
}

/** Turns the kill switch of every probe on. */
export function stopAllScans(reason?: string): Promise<KillSwitchResult> {
  return api.post("/api/v1/scans/stop", { body: reason ? { reason } : {} });
}

/** Turns the kill switch of every probe off. */
export function resumeAllScans(): Promise<KillSwitchResult> {
  return api.post("/api/v1/scans/resume");
}

export function getScanConfig(node: number, signal?: AbortSignal): Promise<ProbeConfigView> {
  return api.get("/api/v1/nodes/{id}/scan-config", { path: { id: node }, signal });
}

/** Replaces the configuration; `revision` is the one read (`If-Match`), absent while none is stored. */
export function updateScanConfig(node: number, config: ScanConfig, revision?: number): Promise<ProbeConfigView> {
  return api.put("/api/v1/nodes/{id}/scan-config", { path: { id: node }, body: config, ifMatch: revision });
}

export function stopNodeScans(node: number, reason?: string): Promise<KillSwitchResult> {
  return api.post("/api/v1/nodes/{id}/scan/stop", { path: { id: node }, body: reason ? { reason } : {} });
}

export function resumeNodeScans(node: number): Promise<KillSwitchResult> {
  return api.post("/api/v1/nodes/{id}/scan/resume", { path: { id: node } });
}
