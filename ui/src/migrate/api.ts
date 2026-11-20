// The only module of the migration views that talks to the API: the mirrored sources
// (Windows takeover plan section 3.2, ADR 0033), their losses and the diff of a mirrored scope.
// A mirror's token travels once, in the answer of its creation or replacement, and is never
// kept by the UI beyond the dialog that shows it.
import { api } from "../api/client";
import type { components } from "../api/generated/schema";

type S = components["schemas"];

export type MirrorItem = S["MirrorItem"];
export type MirrorCreated = S["MirrorCreated"];
export type MirrorLosses = S["MirrorLosses"];
export type MirrorLossItem = S["MirrorLossItem"];
export type ScopeDiff = S["ScopeDiff"];
export type DiffRow = S["DiffRow"];
export type MirroredScope = S["MirroredScope"];

/** The kind label of the Windows DHCP exporter. */
export const WINDOWS_DHCP = "windows-dhcp";

export async function listMirrors(signal?: AbortSignal): Promise<MirrorItem[]> {
  const page = await api.get("/api/v1/migrate/mirrors", { query: { limit: 1000 }, signal });
  return page.items;
}

export function getMirror(id: string, signal?: AbortSignal): Promise<MirrorItem> {
  return api.get("/api/v1/migrate/mirrors/{id}", { path: { id }, signal });
}

/** The source prefixes an operator typed: separated by commas or white space. */
export function sourceList(text: string): string[] {
  return text.split(/[\s,]+/).filter((prefix) => prefix.length > 0);
}

export function createMirror(name: string, intervalSecs: number | null, sources: string[] = []): Promise<MirrorCreated> {
  return api.post("/api/v1/migrate/mirrors", {
    body: { name, kind: WINDOWS_DHCP, interval_secs: intervalSecs ?? undefined, source_prefixes: sources },
  });
}

/** A change of a mirror; `partner: null` takes its pair apart. */
export interface MirrorChange {
  name?: string;
  enabled?: boolean;
  interval_secs?: number;
  partner?: string | null;
}

export function updateMirror(id: string, change: MirrorChange): Promise<MirrorItem> {
  return api.patch("/api/v1/migrate/mirrors/{id}", { path: { id }, body: change });
}

export function deleteMirror(id: string): Promise<undefined> {
  return api.delete("/api/v1/migrate/mirrors/{id}", { path: { id } }) as Promise<undefined>;
}

export function replaceMirrorToken(id: string, sources: string[] = []): Promise<MirrorCreated> {
  return api.post("/api/v1/migrate/mirrors/{id}/token", { path: { id }, body: { source_prefixes: sources } });
}

export function getLosses(id: string, signal?: AbortSignal): Promise<MirrorLosses> {
  return api.get("/api/v1/migrate/mirrors/{id}/losses", { path: { id }, signal });
}

/** Acknowledges entries of the loss report at `sequence`, the one that was shown. */
export function ackLosses(id: string, sequence: number, keys: string[]): Promise<unknown> {
  return api.post("/api/v1/migrate/mirrors/{id}/losses/ack", { path: { id }, body: { sequence, keys } });
}

export function getDiff(id: string, cidr: string, signal?: AbortSignal): Promise<ScopeDiff> {
  return api.get("/api/v1/migrate/mirrors/{id}/scopes/{cidr}/diff", { path: { id, cidr }, signal });
}
