// The only module of the DNS area that talks to the API (docs/dns-contracts.md, section 3):
// zones, their RRsets with the batch change and its dry run, the zone file import and export,
// access lists and TSIG keys, and the audit records of one zone for its history tab.
//
// Some shapes are read wider than the generated types describe them, on the lead's decisions
// for WP4.5 until the regenerated document arrives: a zone may carry `origins` (its RRsets per
// origin), the import report `types` (the records of the file per type), an import without
// `dry_run` answers 202 with a job whose last step keeps the final report as hex-encoded JSON,
// and a change may say `take_over` (the person took over an RRset of another origin; sent only
// when true). Zone bodies never carry `update` until the document has `DnsUpdatePolicy`.
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { fetchAll } from "../api/paginate";
import type { Acl, AclCreate, AclPatch, AuditRecord, BatchResult, DnsKey, ImportReport, KeyCreate, KeyCreated, Origin, RecordChange, RrSet, TransferStatus, Zone, ZoneCreate, ZonePatch } from "./types";

export * from "./types";

/** The list route of the records of a zone, for the grid source. */
export const RECORDS_PATH = "/api/v1/dns/zones/{id}/records";

// ---------------------------------------------------------------------------------
// Zones

export async function listZones(signal?: AbortSignal): Promise<{ items: Zone[]; revision: number }> {
  const all = await fetchAll<Zone>("/api/v1/dns/zones", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

export function getZone(id: string, signal?: AbortSignal): Promise<Zone> {
  return api.get("/api/v1/dns/zones/{id}", { path: { id }, signal }) as Promise<Zone>;
}

export function createZone(body: ZoneCreate): Promise<Zone> {
  return api.post("/api/v1/dns/zones", { body }) as Promise<Zone>;
}

export function updateZone(zone: Pick<Zone, "id" | "revision">, patch: ZonePatch): Promise<Zone> {
  return api.patch("/api/v1/dns/zones/{id}", { path: { id: zone.id }, body: patch, ifMatch: zone.revision }) as Promise<Zone>;
}

export async function deleteZone(id: string): Promise<void> {
  await api.delete("/api/v1/dns/zones/{id}", { path: { id } });
}

/** Whether a zone has any RRset of `origin` (one item read), for the origin mix of the zone list. */
export async function hasOrigin(id: string, origin: Origin, signal?: AbortSignal): Promise<boolean> {
  const page = await api.get("/api/v1/dns/zones/{id}/records", { path: { id }, query: { origin, limit: 1 }, signal });
  return page.items.length > 0;
}

// ---------------------------------------------------------------------------------
// Zone transfers (WP6.1)

/** The transfer state of a zone: the serial held, the sources with their last success and error, the timers. */
export function getZoneTransfer(zoneId: string, signal?: AbortSignal): Promise<TransferStatus> {
  return api.get("/api/v1/dns/zones/{id}/transfer", { path: { id: zoneId }, signal });
}

/** Queues a transfer of a secondary zone now (202); the answer is the state with `running` set. */
export function triggerZoneTransfer(zoneId: string): Promise<TransferStatus> {
  return api.post("/api/v1/dns/zones/{id}/transfer", { path: { id: zoneId }, body: {} as never });
}

// ---------------------------------------------------------------------------------
// Records

/** Every RRset of a zone whose owner starts with `name` (a few at most; the host panel). */
export async function listRecords(id: string, query: { name?: string; type?: string }, signal?: AbortSignal): Promise<RrSet[]> {
  const all = await fetchAll<RrSet>(RECORDS_PATH, { path: { id }, query, signal, max: 1000 });
  return all.items;
}

/** Sends a batch; `dryRun` answers the diff and writes nothing. */
export function changeRecords(id: string, changes: readonly RecordChange[], dryRun: boolean): Promise<BatchResult> {
  return api.post("/api/v1/dns/zones/{id}/records/batch", {
    path: { id },
    query: { dry_run: dryRun || undefined },
    body: { changes: changes.map(wireChange) },
  });
}

function wireChange(change: RecordChange): RecordChange {
  const { take_over, ...rest } = change;
  return take_over ? { ...rest, take_over } : rest;
}

// ---------------------------------------------------------------------------------
// Zone files

export interface ImportInput {
  zoneFile: string;
  replace: boolean;
}

/** The dry run of an import: what the file would add, replace and remove, and what it loses. */
export async function previewImport(id: string, input: ImportInput): Promise<ImportReport> {
  const answer = await api.post("/api/v1/dns/zones/{id}/records/import", {
    path: { id },
    query: { dry_run: true },
    body: { zone_file: input.zoneFile, replace: input.replace },
  });
  if ("job_id" in answer) {
    throw new Error("the dry run of an import answered with a job");
  }
  return answer;
}

/** Applies an import: the server answers with the job that writes it (or, before the job exists, the report). */
export async function applyImport(id: string, input: ImportInput): Promise<{ jobId: string } | { report: ImportReport }> {
  const answer: unknown = await api.post("/api/v1/dns/zones/{id}/records/import", {
    path: { id },
    body: { zone_file: input.zoneFile, replace: input.replace },
  });
  if (answer && typeof answer === "object" && "job_id" in answer && typeof answer.job_id === "string") {
    return { jobId: answer.job_id };
  }
  return { report: answer as ImportReport };
}

/** The final report an import job keeps as the output of its last step (hex-encoded JSON). */
export function importReportOf(job: components["schemas"]["Job"] | undefined): ImportReport | undefined {
  const steps = job?.steps ?? [];
  for (let i = steps.length - 1; i >= 0; i -= 1) {
    const report = decodeReport(steps[i]?.output);
    if (report) return report;
  }
  return undefined;
}

function decodeReport(hex: string | null | undefined): ImportReport | undefined {
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return undefined;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== "object" || !("added" in value) || !("losses" in value)) return undefined;
    return value as ImportReport;
  } catch {
    return undefined;
  }
}

/** Encodes an import report the way the job keeps it (for the mock and tests). */
export function encodeImportReport(report: ImportReport): string {
  return Array.from(new TextEncoder().encode(JSON.stringify(report)), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The zone as a zone file (RFC 1035) in the server's byte-stable order. */
export async function exportZoneFile(id: string): Promise<string> {
  const text: unknown = await api.get("/api/v1/dns/zones/{id}/records/export", {
    path: { id },
    headers: { Accept: "text/dns, text/plain" },
  });
  return typeof text === "string" ? text : "";
}

// ---------------------------------------------------------------------------------
// History

/** The newest audit records of a zone (its changes and its records' changes). */
export async function zoneAudit(id: string, signal?: AbortSignal): Promise<AuditRecord[]> {
  const page = await api.get("/api/v1/audit", { query: { object: `zone:${id}`, limit: 20 }, signal });
  return page.items;
}

// ---------------------------------------------------------------------------------
// Access lists

export async function listAcls(signal?: AbortSignal): Promise<{ items: Acl[]; revision: number }> {
  const all = await fetchAll<Acl>("/api/v1/dns/acls", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

export function createAcl(body: AclCreate): Promise<Acl> {
  return api.post("/api/v1/dns/acls", { body });
}

export function updateAcl(acl: Pick<Acl, "id" | "revision">, patch: AclPatch): Promise<Acl> {
  return api.patch("/api/v1/dns/acls/{id}", { path: { id: acl.id }, body: patch, ifMatch: acl.revision });
}

export async function deleteAcl(id: string): Promise<void> {
  await api.delete("/api/v1/dns/acls/{id}", { path: { id } });
}

// ---------------------------------------------------------------------------------
// TSIG keys (scope dns.keys)

export async function listKeys(signal?: AbortSignal): Promise<{ items: DnsKey[]; revision: number }> {
  const all = await fetchAll<DnsKey>("/api/v1/dns/keys", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

/** Generates a key (no `secret`) or imports one; the answer holds the secret this once. */
export function createKey(body: KeyCreate): Promise<KeyCreated> {
  return api.post("/api/v1/dns/keys", { body });
}

export async function deleteKey(name: string): Promise<void> {
  await api.delete("/api/v1/dns/keys/{key}", { path: { key: name } });
}

// ---------------------------------------------------------------------------------
// Block lists: the file of an uploaded list

/** The route of `upload_dns_list`; the mock's handler listens on it too. */
export const LIST_FILE_PATH = "/api/v1/dns/lists/{id}/file";

/**
 * Sends the file of an uploaded block list (`PUT /dns/lists/{id}/file`, `text/plain` in the
 * list's format, at most `[dns.lists] max_upload`); the answer is the job that compiles it.
 */
export async function uploadBlockList(list: { id: string; revision: number }, text: string): Promise<string> {
  const started = (await api.put(LIST_FILE_PATH, {
    path: { id: list.id },
    body: new Blob([text], { type: "text/plain" }),
    ifMatch: list.revision,
  })) as components["schemas"]["DnsJobStarted"];
  return started.job_id;
}
