// The requests of the block lists page (docs/dns-contracts.md section 3, WP5.2): the lists with
// their newest compiled version, create, change (with `If-Match`), delete, and "fetch now",
// which starts the job that fetches and compiles a URL list. The file of an uploaded list goes
// through `uploadBlockList` in ../api.ts (`PUT /dns/lists/{id}/file`).
//
// A version may carry the `etag` of the fetched file; the page reads it as optional.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { fetchAll } from "../../api/paginate";

type S = components["schemas"];
export type ListVersion = S["ListVersionItem"] & { etag?: string | null };
export type BlockListItem = Omit<S["ListItem"], "version"> & { version?: ListVersion | null };
export type ListCreate = S["ListCreate"];
export type ListPatch = S["ListPatch"];
export type BlockAction = S["BlockAction"];
export type ListFormat = S["ListFormat"];
export type ListSource = S["ListSource"];

export async function listBlockLists(signal?: AbortSignal): Promise<{ items: BlockListItem[]; revision: number }> {
  const all = await fetchAll<BlockListItem>("/api/v1/dns/lists", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

export function createBlockList(body: ListCreate): Promise<BlockListItem> {
  return api.post("/api/v1/dns/lists", { body }) as Promise<BlockListItem>;
}

export function updateBlockList(list: Pick<BlockListItem, "id" | "revision">, patch: ListPatch): Promise<BlockListItem> {
  return api.patch("/api/v1/dns/lists/{id}", { path: { id: list.id }, body: patch, ifMatch: list.revision }) as Promise<BlockListItem>;
}

export async function deleteBlockList(list: Pick<BlockListItem, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dns/lists/{id}", { path: { id: list.id }, ifMatch: list.revision });
}

/** Fetches and compiles a URL list now; the answer is the job that does it. */
export async function fetchBlockList(id: string): Promise<string> {
  const started = await api.post("/api/v1/dns/lists/{id}/fetch", { path: { id } });
  return started.job_id;
}
